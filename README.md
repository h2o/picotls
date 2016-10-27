picotls
===

Picotls is a [TLS 1.3](https://tlswg.github.io/tls13-spec/) implementation written in C.

At the moment, the library implements Draft 18 of the specification. List of supported features are as follows:

* public-key exchange: P256
* aead cipher: AES128-GCM-SHA256
* server-certificates using RSA or ECDSA signatures
* PSK and PSK-DHE
* early-data

Primary goal of the project is to create a fast, tiny TLS 1.3 implementation that can be used with the HTTP/2 protocol stack and possibly the upcoming QUIC stack of the [H2O HTTP/2 server](https://h2o.examp1e.net).

The library only implements the communication protocol.
Cryptographic operations are delegated to OpenSSL using callbacks.
It would be easy to write binding to other crypto engines.

How to
---

Build using cmake:
```
% cmake
% make
% make check
```

Run the test server (at 127.0.0.1:8443):
```
% ./cli -c /path/to/certificate.pem -k /path/to/private-key.pem  127.0.0.1 8443
```

Connect to the test server:
```
% ./cli 127.0.0.1 8443
```

Using resumption:
```
% ./cli -s session-file 127.0.0.1 8443
```
The session-file is read-write.
The cli server implements a single-entry session cache.
The cli server sends NewSessionTicket when it first sends application data after receiving ClientFinished.

Using early-data:
```
% ./cli -s session-file -e 127.0.0.1 8443
```
When `-e` option is used, client first waits for user input, and then sends CLIENT_HELLO along with the early-data.

License
---
MIT
