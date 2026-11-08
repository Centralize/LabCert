# LabCert User Guide

LabCert is your own certificate authority for your home or office network. It creates certificates for your devices and services (NAS, router, Home Assistant, printers, internal websites), so browsers and apps trust them without security warnings.

## How it works in one minute

- An **authority** signs certificates. LabCert creates a **root authority** (the trust anchor) and an **issuing authority** under it that does the everyday signing.
- You **trust the root once** on each device: phone, laptop or server. After that, every certificate LabCert issues is accepted automatically.
- A **certificate** proves that a name (like `nas.home.lan` or `192.168.1.20`) belongs to a device. It comes with a **private key** that must stay secret on that device.
- If a certificate must stop working, you **revoke** it. Devices that check the **revocation list** stop trusting it.

## The window

The menu on the left has these pages:

- **Overview:** counts, certificates that expire soon, recent activity, service status and quick actions.
- **Authorities:** your root and issuing authorities.
- **Certificates:** everything issued, with search and filters.
- **New certificate:** a form to create a certificate and its key.
- **Signing requests:** sign a request made on another machine, and approve network requests.
- **Network service:** the built-in web service for your devices, tokens and ACME.
- **Revocation:** revocation lists and revoked certificates.
- **Activity log:** a record of everything that happened.
- **Settings:** defaults, network name, appearance, backups.
- **Help:** this guide.

The box at the bottom left shows whether the network service is running and lets you start or stop it. Orange numbers next to a menu item mean something needs attention: certificates expiring soon, or requests waiting for approval.

## 1. Set up your authority

1. On the **Overview** page, fill in the name and organization (or keep the suggestions).
2. Choose the key type. *ECDSA P-384* is a good choice for authorities.
3. Keep **Also create an issuing (intermediate) authority** ticked. This is recommended: the root is only used to sign the issuing authority, which limits the damage if anything goes wrong.
4. Click **Create authority**.

### More authorities

On **Authorities** you can:

- **+ New root authority:** a completely separate trust anchor.
- **Import existing…:** use an authority you already have. Paste or open its certificate and private key (PEM). PKCS#8 and RSA (PKCS#1) keys are accepted; password-protected keys must be unlocked first.
- **+ Sub-authority:** create another issuing authority under an existing one.
- **Issue by default:** choose which authority signs new certificates when you don't pick one.
- **Save…:** save the authority's certificate (PEM, or `.cer` for Windows), its chain, or (with a warning) its private key.
- **Trust on this PC** (Windows): add the root to your Windows trust store. Windows asks you to confirm.
- **Details:** fingerprints, serial number, key usage and the certificate text.
- **Revoke…** (sub-authorities only) and **Delete…**. Deleting removes the authority, everything below it and all the certificates it issued from LabCert.

## 2. Trust the root on your devices

This is the step people forget. Until a device trusts your root, it will show warnings.

The easiest way: start the network service (see section 6), then open the **setup page** on the device, for example `http://192.168.1.10:8080/`. It has download buttons and step-by-step instructions:

- **Windows:** open the `.crt` file → *Install Certificate* → *Local Machine* → *Place all certificates in the following store* → *Trusted Root Certification Authorities*.
- **macOS:** open the `.pem` file in *Keychain Access* → choose the *System* keychain → double-click the certificate → *Trust* → *Always Trust*.
- **iPhone / iPad:** download the profile → *Settings → Profile Downloaded → Install*. Then go to *Settings → General → About → Certificate Trust Settings* and turn the root on.
- **Android:** *Settings → Security → Encryption & credentials → Install a certificate → CA certificate*.
- **Linux (Debian/Ubuntu):** copy the `.pem` file to `/usr/local/share/ca-certificates/labcert.crt`, then run `sudo update-ca-certificates`.
- **Firefox** (uses its own list): *Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import*.

Without the service, use *Authorities → Save… → Certificate* and copy the file to the device yourself.

**Check the fingerprint.** The setup page and the authority's details show a SHA-256 fingerprint. They should match what the device shows when you install the root.

## 3. Create a certificate

Go to **New certificate**:

1. **Signed by:** the authority to use (the default is preselected).
2. **Purpose:**
   - *Web / TLS server*: websites, NAS, router, reverse proxy, MQTT and similar.
   - *Client / user login*: a person or device proving who it is.
   - *Server + client*: mutual TLS between services.
   - *Code signing*: scripts and programs.
   - *Email (S/MIME)*: signing and encrypting email.
3. **Main name:** for example `nas.home.lan`.
4. **Other names:** one per line. Host names, IP addresses, `*.wildcards` or email addresses all work. Add every name people actually type, including the IP address if they use it. The buttons below the box add this computer's names, `localhost`, or a wildcard.
5. **Key type:** *ECDSA P-256* works everywhere. Choose *RSA 2048* for very old devices. Avoid Ed25519 for websites; browsers don't accept it.
6. **Valid for:** 1 year is a good default. Apple devices refuse server certificates valid for more than 825 days.
7. Optionally fill in organization details and notes.
8. Click **Create certificate**.

The **Preview** on the right shows exactly what will be in the certificate, and warns about common mistakes.

### Install the certificate on the device

Open the certificate on the **Certificates** page, click **Save…**, and pick the format the device wants:

| Format | Typical use |
|--------|-------------|
| Certificate (`.crt`, PEM) | Most Linux software, together with the key |
| Certificate + intermediates (`fullchain.pem`) | nginx, Apache, Caddy, Traefik, HAProxy, Home Assistant. **Use this one for web servers.** |
| Private key (`.key`) | Goes with the `.crt` / `fullchain.pem` files |
| Key + certificate + chain in one file | HAProxy, some appliances |
| PKCS#12 / PFX (`.pfx`) | Windows, IIS, Synology, QNAP, many routers. You set a password. |
| Certificate (`.cer`, DER) | Windows-only tools |
| Whole chain incl. root | Tools that want the full chain |

Treat key files and PFX files like passwords: copy them directly to the device and delete the copies you don't need.

## 4. Manage certificates

The **Certificates** page lists everything with its status:

- **Valid**: in use and fine.
- **Expiring**: ends within the warning period (30 days by default; see Settings).
- **Expired**, **Revoked**, **On hold**.
- **Replaced**: a newer certificate was made with *Renew*.

Use the search box (names, IP addresses, serial numbers, notes), the status filters, or the authority filter. Click a row to open its details on the right, where you can:

- **Save…** in any format (see above).
- **Renew…**: create a replacement with the same names. Choose a new key (recommended) or keep the old one, set the lifetime, and optionally revoke the old certificate automatically.
- **Revoke…**: choose a reason. *On hold (temporary)* can be undone later with **Release hold**; every other reason is permanent.
- **Delete…**: removes the certificate from LabCert only. It keeps working wherever it is installed, so revoke it first if it should stop.
- **Notes:** where it's installed, who owns it.
- **Certificate text:** show or copy the PEM, with or without the chain.

## 5. Sign a request from another machine (CSR)

Some devices and programs create their own key and give you a *certificate signing request* (CSR). The key never leaves that device, which is the safest option.

1. Go to **Signing requests**.
2. Paste the request text, or click **Open file…**.
3. LabCert checks the request's signature and shows its subject, names and key.
4. Choose the authority, purpose and lifetime. You can add extra names, and keep or drop the requested organization details.
5. Click **Sign request**. Then save the result with **Certificate + intermediates** and give it back to the device.

To create a request yourself with OpenSSL:

```
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout host.key -subj "/CN=host.lan" -addext "subjectAltName=DNS:host.lan,IP:192.168.1.50" -out host.csr
```

## 6. The network service

The network service lets devices help themselves. Start it with **Start service** (sidebar, Overview or Network service page).

### Addresses

The **Network service** page lists the addresses to give to devices, each with a **Copy** button:

- **Setup page:** start here on any device.
- **Root certificate** (`/ca.crt`) and **iPhone/iPad profile** (`/ca.mobileconfig`).
- **Revocation list** (`/crl.crl`).
- **ACME directory:** for automatic certificates.
- **Enrollment:** for token requests.

### Connection settings

- **Listen on:** `0.0.0.0` means every network; `127.0.0.1` means this PC only.
- **Plain (HTTP) and secure (HTTPS) addresses:** turn each on or off and choose its port. The secure address uses a certificate from your own authority, which LabCert creates and renews by itself. Devices must trust your root to use it.
- **Start automatically when LabCert opens.**
- **Publish issued certificates:** makes certificates (never keys) downloadable at `/certs`.

Click **Restart** after changing ports.

### Enrollment tokens

A token lets a machine send a signing request over the network.

1. Click **+ New token**. Give it a label, purpose, lifetime and authority, and optionally limit how many times it can be used and when it expires.
2. Choose **Sign immediately** to issue at once. Otherwise each request waits on the **Signing requests** page for you to click **Approve and sign** or **Reject…**.
3. Copy the token, or the ready-made `curl` command, to the machine:

   ```
   curl --data-binary @host.csr "http://192.168.1.10:8080/api/enroll?token=YOUR_TOKEN" -o host.crt
   ```

   If approval is needed, the reply contains an address the machine can check later (`/api/request/<id>`). It returns the certificate once you approve.

Tokens can be disabled, re-enabled or deleted at any time.

### Automatic certificates (ACME)

ACME is the system Let's Encrypt uses. Tools like certbot, acme.sh, Caddy, Traefik, Home Assistant and pfSense can request and renew certificates from LabCert on their own.

- **Check ownership (http-01):** LabCert connects to port 80 on the requesting machine to confirm it really controls the name. This is the safer choice.
- **Lab mode:** every request is approved without a check, and wildcards are allowed. Use it only on networks you trust.
- **Valid for:** 90 days is typical. Clients renew by themselves.
- **Signed by:** which authority signs ACME certificates.

Examples (replace the address with yours, and give the client your root certificate so it trusts the secure address):

```
certbot certonly --standalone --server https://192.168.1.10:8443/acme/directory -d myhost.lan
```

(certbot: set `REQUESTS_CA_BUNDLE=/path/to/root.pem`)

```
acme.sh --issue --standalone --server https://192.168.1.10:8443/acme/directory --ca-bundle root.pem -d myhost.lan
```

Caddyfile:

```
tls {
    ca https://192.168.1.10:8443/acme/directory
    ca_root /path/to/root.pem
}
```

The **Accounts** list shows every ACME client that has registered. **Block** stops an account from getting further certificates. **Recent requests** shows live what devices ask the service for.

## 7. Revocation

- Revoking a certificate (or a sub-authority) adds it to its authority's **revocation list** immediately.
- Lists are re-signed automatically before they expire (every 7 days by default; see Settings). **Publish a new list now** forces it.
- **Save .crl / .pem** gives you the list for devices that need it as a file.
- So that certificates tell devices *where* to find the list, set **This computer's name on the network** in Settings (for example `labcert.home.lan` or a fixed IP address). The address is then added to every new certificate. It is not added while the name is empty, because an address that can't be reached causes errors on some systems.

## 8. Activity log

Every action is recorded: authorities created, certificates issued, revoked or exported, network requests, ACME orders and errors. Search it, filter by type, **Export CSV…** for a spreadsheet, or **Clear…** it. Clearing the log doesn't affect certificates.

## 9. Settings

- **Certificate defaults:** organization, department, city, state, country, key type, lifetimes and the expiry warning period.
- **Network name and revocation:** the name devices use to reach this computer, whether to put the revocation list address into certificates, and how long lists stay valid.
- **Appearance:** dark or light.
- **Your data:** where the data file is, **Open folder**, **Back up…** and **Restore from backup…**.

## 10. Good practice

- Keep the **root** for signing authorities only; issue everyday certificates from the issuing authority (the default setup does this).
- Make a **backup** after creating authorities, and store it offline. It contains your private keys.
- Prefer **requests (CSR)** or **ACME** so keys are created on the device itself.
- Give each certificate only the names it needs, and use lifetimes of a year or less.
- Revoke certificates for devices you retire or lose.

## 11. Troubleshooting

| Problem | What to do |
|---------|------------|
| Browser still warns "not secure" | The device doesn't trust the root yet (section 2), or the name you typed isn't in the certificate. Check *Names* in the certificate details. Firefox needs the root imported separately. |
| iPhone/Mac says the certificate is "not standards compliant" | The server certificate is valid for more than 825 days. Renew it with a shorter lifetime. |
| Server shows only part of the chain | Install **Certificate + intermediates (fullchain.pem)**, not just the certificate. |
| Service won't start: "Could not open port" | Another program uses the port. Pick another port on the Network service page. |
| Devices can't reach the setup page | Allow LabCert through the Windows firewall for private networks. Check the computer's IP address and that *Listen on* is `0.0.0.0`. |
| ACME client says the connection isn't trusted | Give the client your root certificate (see the examples in section 6), or use the plain HTTP address. |
| ACME validation fails | The requesting machine must answer on port 80 under that name, and LabCert's computer must be able to reach it. Or switch to lab mode on a trusted network. |
| Revocation errors on Windows clients (`CRYPT_E_REVOCATION_OFFLINE`) | The revocation list address in the certificate isn't reachable. Keep the service running, or clear the network name in Settings before issuing. |
| Imported key is refused | Remove its password first, or convert an "EC PRIVATE KEY" with `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key8.pem`. |

## 12. Glossary

- **Authority (CA):** signs certificates. **Root:** the top authority devices trust. **Intermediate / issuing authority:** signed by the root, signs everyday certificates.
- **Certificate:** a signed statement that names belong to a public key.
- **Private key:** the secret that goes with a certificate. Never share it.
- **CSR (signing request):** a request for a certificate, made on the device that keeps the key.
- **Chain:** the certificate plus the authorities above it.
- **CRL (revocation list):** the list of withdrawn certificates.
- **ACME:** the automatic certificate protocol used by Let's Encrypt and many tools.
- **PEM / DER / PFX:** file formats (text, binary, password-protected bundle).
- **Fingerprint:** a short code that identifies a certificate exactly.
