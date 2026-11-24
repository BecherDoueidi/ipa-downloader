# IPA Manager: Phase 0 Proof of Concept

This prototype answers one question: **can an ordinary developer-signed iOS app install a pre-signed IPA onto the same iPhone** through pairing + LocalDevVPN loopback + `installation_proxy`?

It has no UI polish, no signing, no library and no backend. One screen, three buttons, and a log.

## Layout
| Path | What it is |
|---|---|
| `M0-validation-guide.md` | Step M0: check the mechanism on your iPhone with SideStore before trusting this code |
| `bridge/` | Rust static library: a 4-function C ABI over [`idevice`](https://github.com/jkcoxson/idevice) 0.1.68 (MIT) |
| `bridge/include/` | `ipabridge.h` + `module.modulemap` (imported in Swift as `IPABridge`) |
| `app/project.yml` | XcodeGen spec (the `.xcodeproj` is generated in CI) |
| `app/Sources/` | SwiftUI PoC app |
| `.github/workflows/build.yml` | macOS CI: builds the Rust lib, generates the project, builds an **unsigned** IPA artifact |

## Two transport modes (picked automatically from the pairing file)
| Pairing file | iOS | Path in `bridge/src/lib.rs` |
|---|---|---|
| Lockdown (iloader) | 17.4 – 26.3 | TCP `10.7.0.1:62078` → lockdown session → AFC → installation_proxy |
| RPPairing (`idevice_pair` → Remote pairing) | 26.4+ / 27 | TCP `10.7.0.1:<_remotepairing._tcp port>` → pair-verify → TLS-PSK CDTunnel → userspace TCP → RSD → AFC/installation_proxy (RSD) |

The RPPairing sequence mirrors idevice's own `ffi/src/tunnel_provider.rs` (`tunnel_create_rppairing`), which StikDebug uses on the device. The port is found through Bonjour, with a fallback of 49152.

## Build → install → test (no Mac needed)
1. Push this folder to a **public** GitHub repo. CI runs automatically.
2. Download the `IPAPoC-unsigned` artifact (a zip containing `IPAPoC-unsigned.ipa`).
3. On Windows, sign and install it with **iloader** ("Import any IPA") or **Sideloadly**, using your development Apple ID.
4. On the iPhone, with Developer Mode on, Wi-Fi on and **LocalDevVPN connected**:
   1. **Import pairing file…** (the same file you made for M0). The app shows which mode it detected.
   2. RPPairing only: tap **Discover** to find the port.
   3. **Test connection** → milestone M3. Success = the log ends `RESULT: SUCCESS`.
   4. **Choose pre-signed IPA…**, then **Install IPA** → milestone M4. The IPA must already be signed for this device (e.g. signed once with Sideloadly).
   5. Use the share button to export the log.

## Status
- Nothing has been compiled yet. There is no Rust or Swift toolchain on the Windows dev machine, and CI hasn't run.
- Every idevice call was checked by hand against the 0.1.68 source.
- First CI run = first compile check.
