//! Free Apple ID signing (Phase 3 PoC, option B) on top of isideload 0.5.2.
//!
//! Flow for `ipab_sign_and_install`:
//!   1. open a tunnel to this device just long enough to read its UDID + name
//!   2. register the device on the free team (isideload `DevicesApi::ensure_device_registered`)
//!   3. `Sideloader::sign_app` — creates/reuses the development certificate, registers the App ID,
//!      fetches the 7-day profile and signs the bundle on the device
//!   4. open a fresh tunnel and install the signed .app with the existing install path
//!
//! Secrets (certificate private key, anisette state) are stored through `KeychainStorage`, which
//! calls back into Swift; Swift keeps them in the iOS Keychain (this device only).
//! The Apple ID password is only used for the SRP login to gsa.apple.com and is never stored.

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use idevice::IdeviceService;
use idevice::RsdService;
use idevice::lockdown::LockdownClient;
use idevice::tcp::handle::AdapterHandle;
use idevice::utils::installation;
use isideload::anisette::remote_v3::{DEFAULT_ANISETTE_V3_URL, RemoteV3AnisetteProvider};
use isideload::auth::apple_account::{
    AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse,
};
use isideload::dev::developer_session::DeveloperSession;
use isideload::dev::devices::DevicesApi;
use isideload::sideload::builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior};
use isideload::sideload::{SideloaderBuilder, TeamSelection};
use isideload::util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox};
use isideload::util::storage::SideloadingStorage;
use rootcause::prelude::*;

use crate::{
    CONNECT_TIMEOUT, INSTALL_TIMEOUT, MODE_LOCKDOWN, MODE_RPPAIRING, Progress, ProgressCallback,
    StepLog, bytes, lockdown_provider, open_rppairing_tunnel, runtime, string, with_timeout,
    write_out,
};

const MACHINE_NAME: &str = "IPA-PoC";

// ---------------------------------------------------------------------------------------------
// One-time crypto / error-reporting setup
// ---------------------------------------------------------------------------------------------

fn init_once() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Both idevice and isideload use rustls with ring; install it as the process default.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = isideload::init();
    });
}

// ---------------------------------------------------------------------------------------------
// Keychain-backed storage (implemented in Swift)
// ---------------------------------------------------------------------------------------------

/// Swift: store `value` under `key` in the Keychain. Return 0 on success.
pub type StoreFn = extern "C" fn(key: *const c_char, value: *const c_char) -> i32;
/// Swift: return a `strdup`'d copy of the value for `key`, or NULL if absent. Rust frees it.
pub type RetrieveFn = extern "C" fn(key: *const c_char) -> *mut c_char;

static STORE: OnceLock<(StoreFn, RetrieveFn)> = OnceLock::new();

/// Registers the Keychain callbacks. Must be called once before login.
#[unsafe(no_mangle)]
pub extern "C" fn ipab_set_storage_callbacks(store: StoreFn, retrieve: RetrieveFn) {
    let _ = STORE.set((store, retrieve));
}

struct KeychainStorage;

impl SideloadingStorage for KeychainStorage {
    fn store(&self, key: &str, value: &str) -> Result<(), Report> {
        let (store, _) = STORE.get().ok_or_else(|| report!("storage callbacks not set"))?;
        let k = CString::new(key).map_err(|e| report!("{e}"))?;
        let v = CString::new(value).map_err(|e| report!("{e}"))?;
        if store(k.as_ptr(), v.as_ptr()) == 0 {
            Ok(())
        } else {
            Err(report!("Keychain write failed for {key}"))
        }
    }

    fn retrieve(&self, key: &str) -> Result<Option<String>, Report> {
        let (_, retrieve) = STORE.get().ok_or_else(|| report!("storage callbacks not set"))?;
        let k = CString::new(key).map_err(|e| report!("{e}"))?;
        let ptr = retrieve(k.as_ptr());
        if ptr.is_null() {
            return Ok(None);
        }
        let value = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
        unsafe { libc::free(ptr as *mut c_void) };
        // isideload's default `delete` stores "", so treat empty as absent.
        Ok(if value.is_empty() { None } else { Some(value) })
    }
}

// ---------------------------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------------------------

struct Session {
    email: String,
    dev: DeveloperSession,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn report_text(e: &Report) -> String {
    format!("{e:?}")
}

// ---------------------------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------------------------

/// Swift: show the 2FA prompt and block until the user answers. Return a `strdup`'d answer:
/// a 6-digit code, "d" (send to trusted devices), "r" (resend), "p<id>" (SMS to number id),
/// or NULL / "" to abort.
pub type TwoFactorFn = extern "C" fn(prompt: *const c_char, context: *mut c_void) -> *mut c_char;

#[derive(Clone, Copy)]
struct TwoFactorCtx {
    cb: TwoFactorFn,
    ctx: *mut c_void,
}
// Swift keeps the context alive for the duration of the blocking login call.
unsafe impl Send for TwoFactorCtx {}
unsafe impl Sync for TwoFactorCtx {}

fn describe_2fa(p: &TwoFactorCallbackParams) -> String {
    let mut s = String::new();
    if let Some(err) = &p.last_error {
        s.push_str(&format!("Previous attempt failed: {err}\n"));
    }
    if p.unknown {
        s.push_str("Apple did not say where the code was sent. Enter \"d\" to send it to your devices");
    } else if p.sms {
        let to = p
            .numbers
            .iter()
            .find(|n| Some(n.id) == p.selected_number_id)
            .map(|n| n.number_with_dial_code.clone())
            .unwrap_or_else(|| "your phone number".into());
        s.push_str(&format!("Enter the code sent by SMS to {to}"));
    } else {
        s.push_str("Enter the 6-digit code shown on your other Apple devices");
    }
    let others: Vec<String> = p
        .numbers
        .iter()
        .filter(|n| Some(n.id) != p.selected_number_id)
        .map(|n| format!("p{} = SMS to {}", n.id, n.number_with_dial_code))
        .collect();
    if !others.is_empty() {
        s.push_str(&format!(". Or type: {}", others.join(", ")));
    }
    s.push_str(". \"r\" resends.");
    s
}

fn ask_2fa(t: TwoFactorCtx, params: &TwoFactorCallbackParams) -> TwoFactorCallbackResponse {
    let prompt = CString::new(describe_2fa(params).replace('\0', "")).unwrap_or_default();
    let ptr = (t.cb)(prompt.as_ptr(), t.ctx);
    if ptr.is_null() {
        return TwoFactorCallbackResponse::Abort;
    }
    let answer = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().trim().to_string();
    unsafe { libc::free(ptr as *mut c_void) };
    match answer.as_str() {
        "" => TwoFactorCallbackResponse::Abort,
        "d" => TwoFactorCallbackResponse::SendToDevices,
        "r" => TwoFactorCallbackResponse::ResendCode,
        a if a.starts_with('p') => match a[1..].parse::<u32>() {
            Ok(id) => TwoFactorCallbackResponse::SendSms(id),
            Err(_) => TwoFactorCallbackResponse::SubmitCode(answer),
        },
        _ => TwoFactorCallbackResponse::SubmitCode(answer),
    }
}

/// Signs in with an Apple ID (free account is fine) and opens a developer session.
/// Blocking; `two_factor` is called (on a background thread) when Apple asks for a code.
/// Returns 0 on success. `out_message` always receives the step log.
///
/// # Safety
/// Strings must be valid NUL-terminated UTF-8; `context` must outlive the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipab_apple_login(
    email: *const c_char,
    password: *const c_char,
    two_factor: TwoFactorFn,
    context: *mut c_void,
    out_message: *mut *mut c_char,
) -> i32 {
    init_once();
    let mut log = StepLog::new();
    let email = unsafe { string(email) };
    let password = unsafe { string(password) };
    let tf = TwoFactorCtx { cb: two_factor, ctx: context };

    let result: Result<Session, String> = runtime().block_on(async {
        let email = email.ok_or("no Apple ID entered")?;
        let password = password.ok_or("no password entered")?;
        if STORE.get().is_none() {
            return Err("storage callbacks not registered".to_string());
        }
        log.step(format!("anisette server: {DEFAULT_ANISETTE_V3_URL}"));
        let anisette = RemoteV3AnisetteProvider::new(
            DEFAULT_ANISETTE_V3_URL,
            Box::new(KeychainStorage),
            "0".to_string(),
        )
        .map_err(|e| format!("anisette setup failed: {}", report_text(&e)))?;

        log.step("signing in to Apple (SRP to gsa.apple.com)…");
        let mut account: AppleAccount = AppleAccount::builder(&email)
            .anisette_provider(anisette)
            .login(&password, move |params: TwoFactorCallbackParams| async move {
                Ok::<_, Report>(ask_2fa(tf, &params))
            })
            .await
            .map_err(|e| format!("Apple ID login failed: {}", report_text(&e)))?;
        log.step("Apple ID login OK");

        let dev = DeveloperSession::from_account(&mut account)
            .await
            .map_err(|e| format!("developer session failed: {}", report_text(&e)))?;
        log.step("developer session OK");
        Ok(Session { email, dev })
    });

    let code = match result {
        Ok(session) => {
            *SESSION.lock().unwrap() = Some(session);
            log.step("RESULT: SUCCESS — signed in");
            0
        }
        Err(e) => {
            log.step(format!("RESULT: FAILURE — {e}"));
            1
        }
    };
    unsafe { write_out(out_message, log.finish()) };
    code
}

/// 1 if a developer session is open, else 0.
#[unsafe(no_mangle)]
pub extern "C" fn ipab_is_signed_in() -> i32 {
    SESSION.lock().map(|s| s.is_some() as i32).unwrap_or(0)
}

/// Drops the in-memory session (Keychain items are cleared by Swift).
#[unsafe(no_mangle)]
pub extern "C" fn ipab_sign_out() {
    if let Ok(mut s) = SESSION.lock() {
        *s = None;
    }
}

// ---------------------------------------------------------------------------------------------
// Sign + install
// ---------------------------------------------------------------------------------------------

/// Reads UDID + device name over the same transport the install will use.
async fn device_identity(
    mode: i32,
    pairing: &[u8],
    ip: IpAddr,
    port: u16,
    hostname: &str,
    log: &mut StepLog,
) -> Result<(String, String), String> {
    // Keeps the userspace tunnel alive while the lockdown client below uses a stream from it.
    let mut _tunnel: Option<(AdapterHandle, idevice::rsd::RsdHandshake)> = None;
    let mut lockdown = match mode {
        MODE_LOCKDOWN => {
            let provider = lockdown_provider(pairing, ip, log)?;
            let mut l = with_timeout("lockdownd connect", CONNECT_TIMEOUT, LockdownClient::connect(&provider)).await?;
            with_timeout("lockdown StartSession", CONNECT_TIMEOUT, l.start_session(&provider.pairing_file)).await?;
            l
        }
        MODE_RPPAIRING => {
            let (adapter, handshake) =
                open_rppairing_tunnel(pairing, SocketAddr::new(ip, port), hostname, log).await?;
            let (adapter, handshake) = _tunnel.insert((adapter, handshake));
            with_timeout(
                "lockdown over RSD",
                CONNECT_TIMEOUT,
                LockdownClient::connect_rsd(adapter, handshake),
            )
            .await?
        }
        other => return Err(format!("unknown mode {other}")),
    };
    let udid = with_timeout("GetValue(UniqueDeviceID)", CONNECT_TIMEOUT, lockdown.get_value(Some("UniqueDeviceID"), None))
        .await?
        .as_string()
        .map(str::to_owned)
        .ok_or("device returned no UDID")?;
    let name = with_timeout("GetValue(DeviceName)", CONNECT_TIMEOUT, lockdown.get_value(Some("DeviceName"), None))
        .await
        .ok()
        .and_then(|v| v.as_string().map(str::to_owned))
        .unwrap_or_else(|| "iPhone".into());
    Ok((udid, name))
}

/// Signs the IPA at `ipa_path` with the signed-in free Apple ID and installs it on this device.
/// `allow_revoke` != 0 lets isideload revoke old development certificates when the account is
/// at its limit (this breaks apps signed with those certificates, e.g. by SideStore).
/// Progress: 0–50 % signing, 50–100 % installing. Returns 0 on success.
///
/// # Safety
/// Pointers must be valid; `progress_context` must outlive the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipab_sign_and_install(
    mode: i32,
    data: *const u8,
    len: usize,
    ip: *const c_char,
    port: u16,
    hostname: *const c_char,
    ipa_path: *const c_char,
    allow_revoke: i32,
    progress: ProgressCallback,
    progress_context: *mut c_void,
    out_message: *mut *mut c_char,
) -> i32 {
    init_once();
    let mut log = StepLog::new();
    let pairing = unsafe { bytes(data, len) };
    let ip = unsafe { string(ip) };
    let hostname = unsafe { string(hostname) }.unwrap_or_else(|| "ipa-poc".to_string());
    let ipa_path = unsafe { string(ipa_path) };
    let state = Progress { cb: progress, ctx: progress_context };

    let session = SESSION.lock().ok().and_then(|s| s.as_ref().map(|s| (s.email.clone(), s.dev.clone())));

    let result: Result<(), String> = runtime().block_on(async {
        let (email, dev) = session.ok_or("not signed in — sign in with your Apple ID first")?;
        let pairing = pairing.ok_or("no pairing file loaded")?;
        let ip: IpAddr = ip.ok_or("no target IP")?.parse().map_err(|e| format!("invalid target IP: {e}"))?;
        let ipa_path = PathBuf::from(ipa_path.ok_or("no IPA path")?);

        // 1. Device identity (short-lived tunnel)
        let (udid, name) = device_identity(mode, pairing, ip, port, &hostname, &mut log).await?;
        log.step(format!("device: {name} ({udid})"));

        // 2. Sideloader for this run
        let max_certs: MaxCertsBehavior<MaxCertsCallbackBox> =
            if allow_revoke != 0 { MaxCertsBehavior::Revoke } else { MaxCertsBehavior::Error };
        let mut sideloader = SideloaderBuilder::<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>::new(dev, email)
            .team_selection(TeamSelection::First)
            .max_certs_behavior(max_certs)
            // Reuse the main App ID for extensions: free accounts only get 10 App IDs per 7 days.
            .extensions_behavior(ExtensionsBehaviorSelection::Fixed(ExtensionsBehavior::ReuseMain))
            .storage(Box::new(KeychainStorage))
            .machine_name(MACHINE_NAME.to_string())
            .build();

        let team = sideloader.get_team().await.map_err(|e| format!("team lookup failed: {}", report_text(&e)))?;
        log.step(format!("team: {} ({})", team.name.clone().unwrap_or_default(), team.team_id));

        sideloader
            .get_dev_session()
            .ensure_device_registered(&team, &name, &udid, None)
            .await
            .map_err(|e| format!("device registration failed: {}", report_text(&e)))?;
        log.step("device registered on the team");

        // 3. Sign on device
        log.step("signing (certificate, App ID, 7-day profile, codesign)…");
        let (signed_path, _special) = sideloader
            .sign_app(
                ipa_path,
                Some(team),
                false,
                Some(move |p: f32| async move { state.report((p.clamp(0.0, 1.0) * 50.0) as u64) }),
                None,
                Some(&udid),
            )
            .await
            .map_err(|e| format!("signing failed: {}", report_text(&e)))?;
        log.step(format!("signed bundle: {}", signed_path.display()));
        state.report(50);

        // 4. Install over a fresh transport
        let callback = |(pct, p): (u64, Progress)| async move { p.report(50 + pct / 2) };
        let install = match mode {
            MODE_LOCKDOWN => {
                let provider = lockdown_provider(pairing, ip, &mut log)?;
                with_timeout(
                    "install (lockdown)",
                    INSTALL_TIMEOUT,
                    installation::install_package_with_callback(&provider, &signed_path, None, callback, state),
                )
                .await
            }
            _ => {
                let (mut adapter, mut handshake) =
                    open_rppairing_tunnel(pairing, SocketAddr::new(ip, port), &hostname, &mut log).await?;
                with_timeout(
                    "install (RSD)",
                    INSTALL_TIMEOUT,
                    installation::install_package_with_callback_rsd(
                        &mut adapter,
                        &mut handshake,
                        &signed_path,
                        None,
                        callback,
                        state,
                    ),
                )
                .await
            }
        };
        // isideload extracts to <tmp>/<name>.ipa_extracted/Payload/X.app; remove the whole folder.
        let extracted = signed_path
            .ancestors()
            .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy().ends_with("_extracted")))
            .map(|p| p.to_path_buf());
        if let Some(dir) = extracted {
            let _ = std::fs::remove_dir_all(dir);
        }
        install?;
        log.step("installation_proxy reported Complete");
        Ok::<(), String>(())
    });

    let code = match &result {
        Ok(()) => {
            log.step("RESULT: SUCCESS — signed with your Apple ID and installed. Expires in 7 days.");
            0
        }
        Err(e) => {
            log.step(format!("RESULT: FAILURE — {e}"));
            1
        }
    };
    unsafe { write_out(out_message, log.finish()) };
    code
}
