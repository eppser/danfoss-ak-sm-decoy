# Service Tool — TCP 1041

## It is a TLS server

The firmware opens TCP 1041 with the comment `Firewall setup for Service Tool tcp - (1041)`. The
server binary `sm_app` contains the Service Tool implementation under source paths:

```
code/ethernet/ServiceTool/soc.c
code/ethernet/ServiceTool/st_LocalHandler.c
code/ethernet/ServiceTool/st_FileGen.c
code/ethernet/ServiceTool/UploadTask.c
```

and strings `Service Tool Rx`, `Service Tool Tx`, `ServiceToolDid`,
`TFN_Get_ServiceTool_Connection`, `TFN_Set_ServiceTool_Connection`.

The transport is **TLS**. `sm_app` imports, from OpenSSL **1.0.2d**:

```
SSLv23_server_method   SSL_CTX_new   SSL_CTX_use_certificate_file   SSL_CTX_use_PrivateKey_file
SSL_new   SSL_accept   SSL_read   SSL_write
```

and loads its Service Tool key pair from:

```
/danfoss/certs/st_cert.pem
/danfoss/certs/st_privkey.key
```

Note this is a **separate** certificate from the web server's (`/danfoss/certs/cert.pem`). The method
is `SSLv23_server_method`; on OpenSSL 1.0.2d (2015) the practical ceiling is TLS 1.2. The decoy pins
TLS 1.2 with the device cipher list, which is what a modern scanner negotiates.

The genuine certificate is in [`certs/st_cert.pem`](certs/st_cert.pem):

```
subject= C=US, ST=MD, O=Danfoss, OU=SM800A, CN=DanfossSM800A
issuer=  C=US, ST=MD, L=Baltimore, O=Danfoss, OU=Certificate_Authority, CN=SelfSigned-DanfossSM800A
SHA256   2E:23:71:B0:CB:0D:77:29:B4:51:93:01:CB:B6:D3:49:B2:71:40:C0:67:E6:55:B8:33:4F:EA:E7:A2:02:E4:37
```

On the live decoy host the Service Tool port presents **exactly this certificate** (the private key
stays on the operator host and is not in this repo), so the TLS fingerprint matches real AK-SM units.

## The application layer inside TLS — not emulated

Inside the TLS channel the device speaks a proprietary protocol built from **1617 `TFN_*`
("transaction function") handlers** — see [`tfn-catalog.txt`](tfn-catalog.txt). A representative slice:

```
TFN_Get_ServiceTool_Connection   TFN_Set_ServiceTool_Connection
TFN_Put_User_Name   TFN_Put_User_Pass   TFN_Put_Add_User   TFN_Remove_user
TFN_security_login_backoff   TFN_Is_development_code   TFN_Use_email_auth
TFN_Build_scan_PI200_list   TFN_Get_PI_200_Status   TFN_Rescan_show_PI200
```

The decoy does **not** reconstruct this layer. It presents the TLS handshake + certificate and
captures the client's first application bytes, then closes. The TFN protocol is unspecified publicly
and cannot be driven without the real StoreView Desktop client; a fabricated reply inside TLS would
be a worse fingerprint tell than silence, and this decoy never invents a protocol.

## Captured handshake

[`pcaps/servicetool_1041_REALCERT.pcap`](pcaps/) is a TLS handshake on 1041 presenting the genuine
`DanfossSM800A` certificate.
