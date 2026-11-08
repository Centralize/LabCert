# Installing LabCert

LabCert is a single program file. Nothing else needs to be installed on the computer that runs it, and devices on your network only need a web browser.

## 1. What you need

- A computer that stays on while devices need certificates (Windows 10/11 recommended; macOS and Linux also work).
- About 30 MB of disk space.
- To build LabCert yourself: the Rust toolchain from https://rustup.rs (version 1.85 or newer).

## 2. Get the program

### Option A: you already have `labcert.exe`

Copy `labcert.exe` to a folder of your choice, for example `C:\Program Files\LabCert\`, and double-click it. Create a shortcut on the desktop or in the Start menu if you like.

### Option B: build it from the source folder

1. Install Rust from https://rustup.rs (accept the defaults).
2. Open a terminal in the `app` folder.
3. Run:

   ```
   cargo build --release
   ```

4. The finished program is `target\release\labcert.exe` (on macOS/Linux: `target/release/labcert`).

The release build opens without a console window. The debug build (`cargo build`) is fine for trying things out.

On Linux you may need the usual desktop libraries first, for example on Debian/Ubuntu:

```
sudo apt install libgtk-3-dev libxkbcommon-dev libwayland-dev
```

## 3. First start

1. Start LabCert. The Overview page shows a short "Create your authority" form.
2. Keep the suggested values or type your own name and organization, then click **Create authority**. This creates a root authority and an issuing authority under it. It takes a few seconds.
3. Go to **Network service** and click **Start service** if you want devices to download the root certificate or request certificates over the network.

## 4. Windows firewall

The first time the network service starts, Windows asks whether LabCert may communicate on networks. Allow it on **Private networks** (your home or office network). Don't allow public networks unless you really need to.

If you clicked "Cancel" by mistake: open *Windows Security → Firewall & network protection → Allow an app through firewall* and tick LabCert for Private.

Ports used (you can change them on the Network service page):

| Port | Used for |
|------|----------|
| 8080 | Plain web address: setup page, root certificate download, revocation lists, token enrollment, ACME |
| 8443 | Secure (HTTPS) address: the same, encrypted; recommended for ACME clients |
| 80 (outgoing) | Only when ACME checks domain ownership (http-01) on the requesting machine |

## 5. Start automatically

- **Network service:** on the Network service page, tick *Start automatically when LabCert opens*.
- **LabCert itself (Windows):** press `Win + R`, type `shell:startup`, press Enter, and put a shortcut to `labcert.exe` in that folder.

## 6. Where your data is stored

Everything (authorities, private keys, certificates, settings and the activity log) is in one file:

| System | Location |
|--------|----------|
| Windows | `%APPDATA%\LabCert\labcert.json` |
| macOS | `~/Library/Application Support/LabCert/labcert.json` |
| Linux | `~/.local/share/LabCert/labcert.json` |

A copy of the previous version (`labcert.json.bak`) is kept next to it every time it is saved. **Private keys in this file are not encrypted.** Keep the computer's account protected, and keep your backups somewhere safe.

To use a different folder (for example a USB stick or an encrypted drive), start LabCert with:

```
labcert.exe --data-dir "D:\Secure\LabCert"
```

## 7. Back up, move or restore

- **Back up:** *Settings → Your data → Back up…* saves one file with everything in it.
- **Move to a new computer:** install LabCert there, then use *Settings → Restore from backup…* and pick the backup file.
- **Restore** replaces all current data; the old data is kept as a `.bak` file first.

## 8. Update

Close LabCert, replace `labcert.exe` with the new version and start it again. Your data file is kept and read by the new version.

## 9. Uninstall

1. Optional: make a backup (see above).
2. Delete `labcert.exe`.
3. Delete the data folder listed in section 6.
4. If you added the root certificate to devices, remove it from their trust stores. On Windows: run `certmgr.msc` → *Trusted Root Certification Authorities → Certificates*, then delete your LabCert root.

## 10. Command-line options

| Option | What it does |
|--------|--------------|
| `--data-dir <folder>` | Keep the data file in this folder instead of the default |
| `--page <name>` | Open on a page: dashboard, authorities, certificates, issue, requests, server, revocation, activity, settings, help |
| `--selftest` | Run the built-in end-to-end test (creates throw-away data in a temporary folder) and print the results |
| `--demo` | Fill an *empty* data folder with sample data, for trying the app out (use together with `--data-dir`) |
| `--screenshot <file.png>` | Start, draw the window, save a picture to the file and exit; doesn't change any data |

## 11. Checking that it works

Run `labcert.exe --selftest` from a terminal. It creates a test authority, issues and revokes certificates, starts the network service on ports 18480/18443 and runs token enrollment and a full ACME order. It should end with `0 failures`.
