# tlssc

TLS client/server library in C++ for Windows, built on the
[TLSClient](https://github.com/Zero3K/tlsclient) crypto primitives.

## Files

| File | Description |
|---|---|
| `tls.h` | TLS protocol constants and cipher suite enumeration |
| `tlsclient.cpp` | `tls_client` class – connect to a TLS server, send/recv application data |
| `tls_server.h` | `tls_server_conn` class – accept an incoming TCP connection and perform a TLS 1.2 server-side handshake |
| `ecc.c` | P-256 / P-384 ECC primitives (ECDH, ECDSA sign/verify) |
| `gcm.c` | AES-128/256-GCM |
| `sha2.c` | SHA-224/256/384/512 |
| `chacha20.c` | ChaCha20-Poly1305 |
| `lock.h` | Windows `CRITICAL_SECTION` RAII wrapper |
| `chunked_decode.h` | HTTP chunked transfer-encoding decoder |

## Using `tls_server_conn` in an HTTP server

`tls_server_conn` wraps an already-accepted TCP socket and performs a full TLS 1.2
server handshake.  After a successful handshake, `send()` and `recv()` work the same
way as in `tls_client`.

### Requirements

* A DER-encoded X.509 certificate whose Subject Public Key is a **P-256 (secp256r1)**
  ECDSA key.
* The matching **32-byte raw private key** (big-endian scalar).
* Windows SDK (WinSock2, `CryptGenRandom`).

### Supported cipher suites

* `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`  (preferred)
* `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`

### Minimal example (skeleton)

```cpp
#include "tls_server.h"
#pragma comment(lib, "ws2_32.lib")

// DER bytes for a self-signed P-256 certificate (replace with your own).
extern const unsigned char MY_CERT_DER[];
extern const int           MY_CERT_DER_LEN;
// 32-byte raw P-256 private key (big-endian, replace with your own).
extern const unsigned char MY_PRIVKEY[32];

int main()
{
    WSADATA wsad;
    WSAStartup(MAKEWORD(2, 2), &wsad);
    tls_client::init_global();          // initialise AES key-gen tables once

    // Create a listening socket on port 443.
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(443);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(listen_sock, (sockaddr*)&addr, sizeof(addr));
    listen(listen_sock, SOMAXCONN);

    while (true)
    {
        SOCKET client_sock = accept(listen_sock, nullptr, nullptr);

        // Wrap in a TLS server connection.
        tls_server_conn conn;
        conn.init(client_sock, MY_CERT_DER, MY_CERT_DER_LEN, MY_PRIVKEY);

        if (conn.handshake() != nullptr)
        {
            printf("TLS handshake failed: %s\n", conn.errmsg());
            continue;
        }

        // Read the HTTP request.
        char buf[4096];
        int n = conn.recv(buf, sizeof(buf) - 1);
        if (n > 0)
        {
            buf[n] = '\0';
            // ... parse and handle the HTTP request ...

            const char *response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 13\r\n"
                "Connection: close\r\n\r\n"
                "Hello, World!";
            conn.send(response, (int)strlen(response));
        }
        conn.close();
    }

    WSACleanup();
}
```

### Generating a certificate and key

Use OpenSSL to create a self-signed P-256 certificate:

```sh
# Generate private key and self-signed certificate
openssl ecparam -name prime256v1 -genkey -noout -out server.key
openssl req -new -x509 -key server.key -out server.crt -days 365 \
        -subj "/CN=localhost"

# Export DER-encoded certificate
openssl x509 -in server.crt -outform DER -out server.crt.der

# Export raw private key scalar (32 bytes, big-endian)
openssl ec -in server.key -text -noout 2>&1 | grep -A 3 "priv:" \
    | grep -v "priv:" | tr -d ' :\n' | xxd -r -p > server.key.raw
```

Embed the `.der` and `.key.raw` files as byte arrays in your application.