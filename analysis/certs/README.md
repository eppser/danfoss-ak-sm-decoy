# Certificates

These are **public X.509 certificates** present in the publicly downloadable AK-SM 800A firmware.
Certificates are public by nature (a device presents them on every TLS handshake); the matching
**private keys are deliberately not included here** (see below).

## `st_cert.pem` — the Service Tool certificate (`/danfoss/certs/st_cert.pem`)

The certificate the real device presents on **TCP 1041** (Service Tool), loaded by `sm_app` via
`SSL_CTX_use_certificate_file`.

```
subject= C=US, ST=MD, O=Danfoss, OU=SM800A, CN=DanfossSM800A
issuer=  C=US, ST=MD, L=Baltimore, O=Danfoss, OU=Certificate_Authority, CN=SelfSigned-DanfossSM800A
key:     RSA 2048
SHA256   2E:23:71:B0:CB:0D:77:29:B4:51:93:01:CB:B6:D3:49:B2:71:40:C0:67:E6:55:B8:33:4F:EA:E7:A2:02:E4:37
```

## `base_os_certs.pem` — certificate(s) found in the base-OS image

Reference copy of the device certificate as found in the rootfs image.

## Private keys — not republished

The firmware also contains the matching private keys (`st_privkey.key`, the web `privkey.key`, and
several keys in the base-OS image). They are **not** included in this repository. They are a
self-signed factory default shared across devices and are trivially extractable from the public
firmware by anyone who wants them, so including them here would add no analytical value while making
it marginally easier to impersonate a real Danfoss device. The live decoy loads its key material
from the operator host, never from this repo.

The decoy's `install.sh` **generates its own** cert/key pair at install time with the same subject
(`CN=DanfossSM800A`) signed by a self-signed `SelfSigned-DanfossSM800A` CA, so an installed decoy
presents a faithful-looking certificate without anyone needing the factory key.
