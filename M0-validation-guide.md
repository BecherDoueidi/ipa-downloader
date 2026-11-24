# M0: Check the Install Mechanism on Your iPhone (No Code)

**Goal:** find out whether same-device installation (pairing file + LocalDevVPN + installation service) works on **your** iPhone and iOS version, using existing tools. If SideStore can't install an IPA on your phone, the IPA Manager prototype won't be able to either.

**Time:** 1 to 3 hours. **Cost:** free. **You need:** your iPhone, a USB cable, your Windows PC (64-bit, not ARM), Wi-Fi.

> Write down everything in the **Results log** at the bottom as you go. Those notes decide which pairing method the prototype has to use.

---

## Step 1: Record your starting point (2 min)
On the iPhone, open **Settings › General › About** and note:
- iPhone model
- iOS version (e.g. 26.3, 26.5, 27.1)

Find your row. It tells you which **pairing path** you're on:

| Your iOS | Pairing file you need | Computer needed for pairing? |
|---|---|---|
| 17.4 – 26.3 | Classic **lockdown** pairing file (iloader makes it) | Yes, once |
| 26.4 – 26.7 | **Remote pairing (RPPairing)** file (`idevice_pair` makes it) | Yes, once |
| 27.0+ | Remote pairing file. On-device pairing has been *reported* but has open bugs | Use the PC route for M0 |
| Below 17.4 | Not supported by current tools | Stop: update iOS or use another device |

## Step 2: Decide which Apple ID to use (2 min)
iloader and SideStore sign apps with an Apple ID: your login goes to Apple, and SideStore also uses an "anisette" server. **Use a secondary Apple ID made just for development** rather than your main account. A free account is fine for M0: it allows 3 sideloaded apps, 7-day signatures, and 10 App IDs per week.

## Step 3: Prepare Windows (10 min)
1. Install **iTunes** (from the Microsoft Store or apple.com). iloader needs Apple's USB driver from it.
2. Download **iloader** from the official sources only: **https://iloader.app** or **https://github.com/nab138/iloader** (the MSI installer is recommended).
3. **Only if you're on iOS 26.4 or later:** also get **`idevice_pair`** from jkcoxson's idevice project (https://github.com/jkcoxson/idevice; check its releases/tools).

## Step 4: Prepare the iPhone (5 min)
1. Connect to **Wi-Fi**. Mobile data alone isn't enough for this mechanism.
2. Install **LocalDevVPN** from the App Store (publisher: Coxson Engineering LLC). Don't turn it on yet.
3. Turn **off** any DNS blockers or other VPNs (NextDNS, AdGuard, WireGuard, and so on). They're a known cause of failures.
4. Make sure the phone has a passcode set. Pairing depends on it, and **changing the passcode later invalidates the pairing file**.

## Step 5: Pair the iPhone with the PC (5 min)
1. Plug the iPhone into the PC with USB and unlock it.
2. Tap **Trust** on the iPhone and enter your passcode.
3. Open iloader. Your device should appear.

## Step 6: Install SideStore with iloader (10 min)
1. In iloader, **sign in with the Apple ID** from Step 2.
2. Choose **Install SideStore**. The plain version is better for M0 than the LiveContainer + SideStore bundle, which has extra open pairing bugs on iOS 27.
3. Wait until iloader reports success. SideStore now appears on the Home Screen.

## Step 7: Turn on Developer Mode and trust the developer (5 min)
1. On the iPhone: **Settings › Privacy & Security › Developer Mode** → on. The phone restarts. After the restart, confirm **Turn On**. (The Developer Mode switch only shows up once a developer-signed app is installed, which is why this step comes after Step 6.)
2. If SideStore says "Untrusted Developer" when opened: **Settings › General › VPN & Device Management** → your Apple ID → **Trust**.

## Step 8: Place the pairing file (10 min)

**iOS 17.4 – 26.3 (lockdown pairing):**
1. In iloader: **Manage Pairing File** → click **Place** next to **SideStore**.
2. USB is the most reliable connection for this step.

**iOS 26.4 or later (remote pairing):**
1. Run `idevice_pair` → **Remote pairing** → **Create** → **Save to file…**
2. Get the file onto the iPhone (AirDrop isn't available from Windows; use iCloud Drive, OneDrive, or email it to yourself), save it to Files, then import it in SideStore when it asks for a pairing file (or under **SideStore › Settings**).
3. If SideStore rejects it, also try iloader's **Place** and note which one worked.

> 🔐 The pairing file works like a trusted-computer key for your phone. Don't share it or upload it anywhere.

## Step 9: Connect LocalDevVPN and open SideStore (2 min)
1. Open LocalDevVPN and **connect**. Allow the VPN configuration if asked.
2. Open SideStore. If it asks you to sign in, use the same Apple ID.
3. **First checkpoint:** in SideStore's **My Apps**, tap **Refresh All** (or the "7 DAYS" badge on SideStore itself). A successful refresh means the app talked to the phone's own device services through the VPN.
   - ✅ Refresh succeeded → the connection works. Go to Step 10.
   - ❌ Failure → go to **Troubleshooting**, write down the exact error code and text.

## Step 10: Install a test IPA (10 min). This is the real M0 test
1. Get a small, **legally distributable** IPA, such as an open-source app that publishes `.ipa` files in its GitHub Releases. Don't use cracked or decrypted App Store apps: they cause false failures and legal trouble.
2. Save the `.ipa` into the Files app.
3. LocalDevVPN connected → SideStore → **My Apps** → **+** → pick the IPA.
4. Wait for SideStore to sign and install it.
5. Open the installed app from the Home Screen.

**M0 passes when:** the app installs, its icon appears, and it launches.

## Step 11: Quick reliability checks (spread over 1 to 3 days, 10 min each)
These give early reliability data for the prototype's decision:
- [ ] Restart the iPhone → connect LocalDevVPN → Refresh All. Still works?
- [ ] Turn LocalDevVPN off and on → Refresh. Still works?
- [ ] Without the VPN connected, try Refresh. It *should* fail; note the error text.
- [ ] Next day: refresh again without touching the PC.
- [ ] Remove the test app and install it again.

---

## Troubleshooting (from SideStore's official docs)

| Symptom / error | What to try |
|---|---|
| "Not connected to Wi-Fi / VPN" or connection errors | Confirm Wi-Fi + LocalDevVPN are on, DNS blockers off, restart the iPhone, reconnect the VPN |
| **Error 1006**: can't determine UDID / invalid pairing | In SideStore **Settings → Reset Pairing File**; in iloader delete the stored pairing; re-Trust, re-pair, **Place** again. As a fallback, set SideStore **Settings › VPN Configuration › Device IP = 10.7.0.1** |
| **Error 27** on iOS 26.4+ | Install the **SideStore nightly** build (iloader can do it) |
| "rppairing UDID not found" / "PairVerifyFailed" (iOS 27) | Regenerate a **Remote pairing** file with `idevice_pair`, import it, and use plain SideStore (not the LiveContainer bundle). These are known open issues (#1707, #1740) |
| AFC connection failure | Use LocalDevVPN (not WireGuard/StosVPN), disable DNS blockers, restart, replace the pairing file |
| **Error 1009**: App ID limit | Free accounts get 10 App IDs per 7 days. Wait, or use fewer test apps |
| Sign-in fails | SideStore Settings → switch the anisette server |
| Installed app won't open | Check Developer Mode is on and the developer is trusted (Step 7) |
| Pairing file stops working after an iOS update or passcode change | Expected. Re-pair with the PC (Steps 5 and 8) |

Logs: iloader saves logs in `%APPDATA%\me.nabdev.iloader\logs`. Keep them if something fails.

---

## Results log (fill this in)

| Item | Your result |
|---|---|
| iPhone model | |
| iOS version | |
| Pairing type that worked (lockdown / remote) | |
| Tool that created it (iloader / idevice_pair) | |
| SideStore version (release / nightly) | |
| Step 9 refresh: pass / fail (+ error) | |
| Step 10 IPA install: pass / fail (+ error) | |
| Installed app launches? | |
| After reboot still works? | |
| VPN off → error text | |
| Next-day refresh works? | |
| Anything odd | |

## What the result means

| Outcome | Next step |
|---|---|
| ✅ Step 10 passes | **GO to M1** (prototype toolchain). The prototype targets the pairing type you recorded |
| ⚠️ Refresh works but IPA install fails | Usually a problem with the IPA or the signing, not the mechanism. Try a different, small, open-source IPA |
| ❌ Step 9 fails even after troubleshooting | The mechanism is currently broken on your iOS version. Check the SideStore GitHub issues for your version; wait for a fix or test on another device. Don't start M1 yet |
