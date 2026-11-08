# LabCert: local network certificate authority

LabCert is a desktop app that runs your own certificate authority for your home or office network. It creates, renews and revokes certificates. Its built-in network service hands out the root certificate and revocation lists, accepts signing requests with enrollment tokens, and speaks ACME, so tools like certbot, Caddy and Traefik can renew on their own.

- **Installation:** [docs/INSTALL.md](docs/INSTALL.md)
- **User guide:** [docs/USER_GUIDE.md](docs/USER_GUIDE.md); also available inside the app on the **Help** page.

Quick start:

```
cargo build --release
target\release\labcert.exe
```
