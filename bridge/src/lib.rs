//! ipabridge — Phase 0 proof-of-concept bridge.
//!
//! Exposes a tiny C ABI (see `include/ipabridge.h`) so the Swift app never has to touch the
//! idevice API directly. Two transport modes, matching the Phase 0 report:
//!
//! * `MODE_LOCKDOWN` (iOS 17.4 – 26.3): classic lockdown pairing file, TCP to lockdownd at
//!   `<ip>:62078` through LocalDevVPN, then AFC + installation_proxy.
//! * `MODE_RPPAIRING` (iOS 26.4+ / 27): RPPairing file, raw remote-pairing handshake at
//!   `<ip>:<_remotepairing._tcp port>`, TLS-PSK CDTunnel, userspace TCP stack, RSD, then the
//!   RSD variants of AFC + installation_proxy.
//!
//! The RPPairing sequence mirrors idevice's own `ffi/src/tunnel_provider.rs`
//! (`tunnel_create_rppairing` + `finish_tunnel`), which StikDebug uses on-device.
//!
//! Every exported function is blocking; call it from a background thread.

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use idevice::IdeviceError;
use idevice::IdeviceService;
use idevice::lockdown::LockdownClient;
use idevice::pairing_file::PairingFile;
use idevice::provider::TcpProvider;
use idevice::remote_pairing::{
    RemotePairingClient, RpPairingFile, RpPairingSocket, connect_tls_psk_tunnel_native,
};
use idevice::rsd::RsdHandshake;
use idevice::tcp::adapter::Adapter;
use idevice::tcp::handle::AdapterHandle;
use idevice::utils::installation;

pub const MODE_LOCKDOWN: i32 = 0;
pub const MODE_RPPAIRING: i32 = 1;

pub const PAIRING_INVALID: i32 = -1;
pub const PAIRING_LOCKDOWN: i32 = 1;
pub const PAIRING_RPPAIRING: i32 = 2;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
const LABEL: &str = "ipa-poc";

// ---------------------------------------------------------------------------------------------
// Runtime + logging helpers
// ---------------------------------------------------------------------------------------------

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to build tokio runtime")
    })
}

/// Step-by-step log returned to Swift so every attempt leaves a readable trace.
struct StepLog {
    start: Instant,
    lines: Vec<String>,
}

impl StepLog {
    fn new() -> Self {
        Self { start: Instant::now(), lines: Vec::new() }
    }
    fn step(&mut self, msg: impl AsRef<str>) {
        let ms = self.start.elapsed().as_millis();
        self.lines.push(format!("[+{ms:>6} ms] {}", msg.as_ref()));
    }
    fn finish(self) -> String {
        self.lines.join("\n")
    }
}

fn err_text(e: &IdeviceError) -> String {
    format!("{e} ({e:?})")
}

/// Writes `text` into `*out` as a heap C string the caller frees with `ipab_free_string`.
unsafe fn write_out(out: *mut *mut c_char, text: String) {
    if out.is_null() {
        return;
    }
    let cleaned = text.replace('\0', "?");
    let c = CString::new(cleaned).unwrap_or_default();
    unsafe { *out = c.into_raw() };
}

unsafe fn bytes<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok().map(str::to_owned)
}

async fn with_timeout<T>(
    what: &str,
    dur: Duration,
    fut: impl std::future::Future<Output = Result<T, IdeviceError>>,
) -> Result<T, String> {
    match tokio::time::timeout(dur, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{what} failed: {}", err_text(&e))),
        Err(_) => Err(format!("{what} timed out after {}s", dur.as_secs())),
    }
}

// ---------------------------------------------------------------------------------------------
// Progress callback plumbing
// ---------------------------------------------------------------------------------------------

pub type ProgressCallback = Option<extern "C" fn(percent: u64, context: *mut c_void)>;

#[derive(Clone, Copy)]
struct Progress {
    cb: ProgressCallback,
    ctx: *mut c_void,
}
// The Swift side guarantees the context outlives the blocking call.
unsafe impl Send for Progress {}
unsafe impl Sync for Progress {}

impl Progress {
    fn report(&self, pct: u64) {
        if let Some(cb) = self.cb {
            cb(pct, self.ctx);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Transport setup
// ---------------------------------------------------------------------------------------------

fn lockdown_provider(pairing: &[u8], ip: IpAddr, log: &mut StepLog) -> Result<TcpProvider, String> {
    let pairing_file = PairingFile::from_bytes(pairing)
        .map_err(|e| format!("lockdown pairing file did not parse: {}", err_text(&e)))?;
    log.step(format!(
        "lockdown pairing file parsed (UDID {})",
        pairing_file.udid.clone().unwrap_or_else(|| "<missing>".into())
    ));
    Ok(TcpProvider { addr: ip, scope_id: None, pairing_file, label: LABEL.to_string() })
}

/// RPPairing → TLS-PSK CDTunnel → userspace TCP → RSD handshake.
async fn open_rppairing_tunnel(
    pairing: &[u8],
    addr: SocketAddr,
    hostname: &str,
    log: &mut StepLog,
) -> Result<(AdapterHandle, RsdHandshake), String> {
    let mut rpf = RpPairingFile::from_bytes(pairing)
        .map_err(|e| format!("RPPairing file did not parse: {}", err_text(&e)))?;
    log.step(format!("RPPairing file parsed (identifier {})", rpf.identifier()));

    log.step(format!("TCP connect to remote pairing service at {addr}"));
    let stream = with_timeout("remote pairing TCP connect", CONNECT_TIMEOUT, async {
        Ok(tokio::net::TcpStream::connect(addr).await?)
    })
    .await?;
    log.step("TCP connected");

    let mut rpc = RemotePairingClient::new(RpPairingSocket::new(stream), hostname);
    with_timeout("pair-verify", CONNECT_TIMEOUT, rpc.connect(&mut rpf, || async {
        "000000".to_string()
    }))
    .await?;
    log.step("pair-verify OK (device accepted the pairing file)");

    let tunnel_port =
        with_timeout("create_tcp_listener", CONNECT_TIMEOUT, rpc.create_tcp_listener()).await?;
    log.step(format!("device opened tunnel listener on port {tunnel_port}"));

    let mut tunnel_addr = addr;
    tunnel_addr.set_port(tunnel_port);
    let tunnel_stream = with_timeout("tunnel TCP connect", CONNECT_TIMEOUT, async {
        Ok(tokio::net::TcpStream::connect(tunnel_addr).await?)
    })
    .await?;
    let tunnel = with_timeout(
        "TLS-PSK + CDTunnel handshake",
        CONNECT_TIMEOUT,
        connect_tls_psk_tunnel_native(tunnel_stream, rpc.encryption_key()),
    )
    .await?;
    log.step(format!(
        "CDTunnel up: client {} -> server {}, mtu {}, RSD port {}",
        tunnel.info.client_address, tunnel.info.server_address, tunnel.info.mtu, tunnel.info.server_rsd_port
    ));

    let client_ip: IpAddr = tunnel
        .info
        .client_address
        .parse()
        .map_err(|e| format!("bad tunnel client address: {e}"))?;
    let server_ip: IpAddr = tunnel
        .info
        .server_address
        .parse()
        .map_err(|e| format!("bad tunnel server address: {e}"))?;
    let mtu = tunnel.info.mtu as usize;
    let rsd_port = tunnel.info.server_rsd_port;

    let raw = tunnel.into_inner();
    let mut adapter = Adapter::new(Box::new(raw), client_ip, server_ip);
    adapter.set_mss(mtu.min(8192) - 60);
    let mut adapter = adapter.to_async_handle();

    let rsd_stream = match tokio::time::timeout(CONNECT_TIMEOUT, adapter.connect(rsd_port)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(format!("RSD connect through tunnel failed: {e}")),
        Err(_) => return Err("RSD connect through tunnel timed out".into()),
    };
    let handshake =
        with_timeout("RSD handshake", CONNECT_TIMEOUT, RsdHandshake::new(rsd_stream)).await?;
    log.step(format!(
        "RSD handshake OK: {} services, device UUID {}",
        handshake.services.len(),
        handshake.uuid
    ));
    Ok((adapter, handshake))
}

// ---------------------------------------------------------------------------------------------
// Exported C ABI
// ---------------------------------------------------------------------------------------------

/// Returns a static version string. Do not free.
#[unsafe(no_mangle)]
pub extern "C" fn ipab_version() -> *const c_char {
    static V: OnceLock<CString> = OnceLock::new();
    V.get_or_init(|| {
        CString::new(format!("ipabridge {} (idevice 0.1.68)", env!("CARGO_PKG_VERSION"))).unwrap()
    })
    .as_ptr()
}

/// Frees a string produced by this library.
///
/// # Safety
/// `s` must come from an `out_message` of this library, or be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipab_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Detects which kind of pairing file `data` is.
/// Returns `PAIRING_LOCKDOWN` (1), `PAIRING_RPPAIRING` (2) or `PAIRING_INVALID` (-1).
///
/// # Safety
/// `data` must point to `len` readable bytes. `out_message` may be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipab_inspect_pairing(
    data: *const u8,
    len: usize,
    out_message: *mut *mut c_char,
) -> i32 {
    let Some(data) = (unsafe { bytes(data, len) }) else {
        unsafe { write_out(out_message, "empty pairing file".into()) };
        return PAIRING_INVALID;
    };
    let lockdown_err = match PairingFile::from_bytes(data) {
        Ok(pf) => {
            let udid = pf.udid.unwrap_or_else(|| "<missing>".into());
            unsafe { write_out(out_message, format!("Lockdown pairing file, UDID {udid}")) };
            return PAIRING_LOCKDOWN;
        }
        Err(e) => err_text(&e),
    };
    match RpPairingFile::from_bytes(data) {
        Ok(rpf) => {
            unsafe {
                write_out(out_message, format!("RPPairing file, identifier {}", rpf.identifier()))
            };
            PAIRING_RPPAIRING
        }
        Err(e) => {
            unsafe {
                write_out(
                    out_message,
                    format!(
                        "Not a recognised pairing file.\n  as lockdown: {lockdown_err}\n  as RPPairing: {}",
                        err_text(&e)
                    ),
                )
            };
            PAIRING_INVALID
        }
    }
}

/// Milestone M3: establishes an authenticated session with this device's own services and
/// reports the iOS version (lockdown) or RSD service count (RPPairing).
/// Returns 0 on success, non-zero on failure. `out_message` always receives the step log.
///
/// # Safety
/// Pointers must be valid; `data` must point to `len` bytes; strings must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipab_test_connection(
    mode: i32,
    data: *const u8,
    len: usize,
    ip: *const c_char,
    port: u16,
    hostname: *const c_char,
    out_message: *mut *mut c_char,
) -> i32 {
    let mut log = StepLog::new();
    let pairing = unsafe { bytes(data, len) };
    let ip = unsafe { string(ip) };
    let hostname = unsafe { string(hostname) }.unwrap_or_else(|| LABEL.to_string());

    let result: Result<(), String> = runtime().block_on(async {
        let pairing = pairing.ok_or("no pairing file loaded")?;
        let ip: IpAddr = ip
            .ok_or("no target IP")?
            .parse()
            .map_err(|e| format!("invalid target IP: {e}"))?;
        match mode {
            MODE_LOCKDOWN => {
                let provider = lockdown_provider(pairing, ip, &mut log)?;
                log.step(format!("TCP connect to lockdownd at {ip}:{}", LockdownClient::LOCKDOWND_PORT));
                let mut lockdown =
                    with_timeout("lockdownd connect", CONNECT_TIMEOUT, LockdownClient::connect(&provider))
                        .await?;
                log.step("TCP connected to lockdownd");
                with_timeout("lockdown StartSession", CONNECT_TIMEOUT, lockdown.start_session(&provider.pairing_file))
                    .await?;
                log.step("StartSession OK (TLS session with the pairing record)");
                let version = with_timeout(
                    "GetValue(ProductVersion)",
                    CONNECT_TIMEOUT,
                    lockdown.get_value(Some("ProductVersion"), None),
                )
                .await?;
                log.step(format!("Device reports iOS {:?}", version.as_string().unwrap_or("?")));
                Ok::<(), String>(())
            }
            MODE_RPPAIRING => {
                let (_adapter, handshake) =
                    open_rppairing_tunnel(pairing, SocketAddr::new(ip, port), &hostname, &mut log).await?;
                let mut names: Vec<&String> = handshake
                    .services
                    .keys()
                    .filter(|k| k.contains("installation_proxy") || k.contains("afc"))
                    .collect();
                names.sort();
                log.step(format!("install-related RSD services: {names:?}"));
                Ok(())
            }
            other => Err(format!("unknown mode {other}")),
        }
    });

    let code = match &result {
        Ok(()) => {
            log.step("RESULT: SUCCESS");
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

/// Milestone M4: uploads the IPA at `ipa_path` to PublicStaging over AFC and asks
/// installation_proxy to install it. The IPA must already be signed for this device.
/// Returns 0 on success, non-zero on failure. `out_message` always receives the step log.
///
/// # Safety
/// Pointers must be valid; `progress_context` must outlive the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipab_install_ipa(
    mode: i32,
    data: *const u8,
    len: usize,
    ip: *const c_char,
    port: u16,
    hostname: *const c_char,
    ipa_path: *const c_char,
    progress: ProgressCallback,
    progress_context: *mut c_void,
    out_message: *mut *mut c_char,
) -> i32 {
    let mut log = StepLog::new();
    let pairing = unsafe { bytes(data, len) };
    let ip = unsafe { string(ip) };
    let hostname = unsafe { string(hostname) }.unwrap_or_else(|| LABEL.to_string());
    let ipa_path = unsafe { string(ipa_path) };
    let state = Progress { cb: progress, ctx: progress_context };

    let result: Result<(), String> = runtime().block_on(async {
        let pairing = pairing.ok_or("no pairing file loaded")?;
        let ip: IpAddr = ip
            .ok_or("no target IP")?
            .parse()
            .map_err(|e| format!("invalid target IP: {e}"))?;
        let ipa_path = ipa_path.ok_or("no IPA path")?;
        let ipa = tokio::fs::read(&ipa_path)
            .await
            .map_err(|e| format!("could not read IPA at {ipa_path}: {e}"))?;
        log.step(format!("read IPA: {} bytes", ipa.len()));

        let callback = |(pct, p): (u64, Progress)| async move { p.report(pct) };

        match mode {
            MODE_LOCKDOWN => {
                let provider = lockdown_provider(pairing, ip, &mut log)?;
                log.step("AFC upload to PublicStaging + installation_proxy Install (lockdown)…");
                with_timeout(
                    "install (lockdown)",
                    INSTALL_TIMEOUT,
                    installation::install_bytes_with_callback(&provider, ipa, None, callback, state),
                )
                .await?;
            }
            MODE_RPPAIRING => {
                let (mut adapter, mut handshake) =
                    open_rppairing_tunnel(pairing, SocketAddr::new(ip, port), &hostname, &mut log).await?;
                log.step("AFC upload to PublicStaging + installation_proxy Install (RSD)…");
                with_timeout(
                    "install (RSD)",
                    INSTALL_TIMEOUT,
                    installation::install_bytes_with_callback_rsd(
                        &mut adapter,
                        &mut handshake,
                        ipa,
                        None,
                        callback,
                        state,
                    ),
                )
                .await?;
            }
            other => return Err(format!("unknown mode {other}")),
        }
        log.step("installation_proxy reported Complete");
        Ok::<(), String>(())
    });

    let code = match &result {
        Ok(()) => {
            log.step("RESULT: SUCCESS — check the Home Screen, then launch the app");
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
