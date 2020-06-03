picotcpls
===

Picotcpls is a fork of [picotls](https://github.com/h2o/picotls), a  [TLS 1.3 (RFC 8446)](https://tools.ietf.org/html/rfc8446) protocol stack written in C, with the following features:

* From picotls:
  * support for two crypto engines
    * "OpenSSL" backend using libcrypto for crypto and X.509 operations
    * "minicrypto" backend using [cifra](https://github.com/ctz/cifra) for most crypto and [micro-ecc](https://github.com/kmackay/micro-ecc) for secp256r1
  * support for PSK, PSK-DHE resumption using 0-RTT
  * API for dealing directly with TLS handshake messages (essential for QUIC)
  * support for new extensions: Encrypted SNI (wg-draft-02), Certificate Compression (wg-draft-10)
* From TCPLS:
  * API to deal with a novel TCP extensibility mechanism
    * Allows setting and configuring the peer's TCP stack for our
      connections
    * Can inject BPF bytecode to the peer to set a new congestion
      control mechanism
    * Essentially any TCP socket option (a few are supported so far)
  * A wrapper to handle network connections
  * QUIC-like streams
  * A Failover mechanism
  * (ongoing: Authenticated connection closing)
  * (ongoing: multipathing)


picotcpls is a research-level implementation of TCPLS, a novel
cross-layer extensibility mechanism for TCP designed to offer a
fine-grained control of the transport protocol to the application layer.
The mere existence of this research comes from several observations:

* TLS is now massively deployed, and we should not expect unsecure TCP
  connections to occur over untrusted networks anymore.
* TCP suffers from severe extensibility issues caused by middlebox
  interferences, lack of space in its header and the difficulty to
  propagate new implementation features
* There is a performance gap between what some application usage get
  (e.g., web), and what they could expect to get with proper
  configuration of the transport layer to match their usage of the
  network.

The goals of TCPLS are threefolds:

* Providing a simple API to the application layer
* Showing that alternative extensibility mechanisms can be powerful
* Showing the quest for maximum Web performance with QUIC can be matched by
  TCPLS, or even improved under several metrics.

Like picotls, the implementation of picotcpls is licensed under the MIT license.


Building picotcpls
---

If you have cloned picotpls from git then ensure that you have initialised the submodules:
```
% git submodule init
% git submodule update
```

Build using cmake:
```
% cmake .
% make
% make check
```

Usage documentation
---

### Overview

This is an overview of an ongoing research and development project. Many
things are missing and some features may change in the future. The
current description is intented to provide an intuition of the potential usefulness
TCPLS.

### Initializing the Context

picotcpls currently use picotls's context. First, follow the
[guideline](https://github.com/h2o/picotls/wiki/Using-picotls#initializing-the-context)
provided by picotls's wiki to manipulate a `ptls_context_t ctx` to setup
SSL. This context is meant to be a static attribute common to many TCPLS
connections; hence its configuration is supposed to be common to all of
them.

Regarding TCPLS, client and server must advertise support for TCPLS. In
our implementation, this exchange of information is going to be
triggered by setting  

`ctx.support_tcpls_options = 1`  

The TLS handshake is designed to only expose the information that we're
doing TCPLS, but not how exactly we configure the new TLS/TCP stack, for
which the information is private to a passive observer (assuming no
side-channels).  

### Managing the Connection Object

Similarly to picotls, we offer a creation and a destruction function.
The `tcpls_new` function takes as argument a `ptls_context_t*` and a
boolean value indicating whether the connection is server side or not.  

`tcpls_t *tcpls = tcpls_new(&ctx, is_server);`  

The application is responsible for freeing its memory, using
`tcpls_free(tcpls)` when the connection wants to be closed.  

A tcpls connection may have multiple addresses and streams attached
them. Addresses require to be added first if we expect to use them for
connections.  

### Adding addresses

picotls supports both v4 and v6 IP addresses, which the application can
advertize by calling   

`tcpls_add_v4(ptls_t *tls, struct sockaddr_in
*addr, int is_primary, int settopeer, int is_ours)`  

or  

`tcpls_add_v6(ptls_t *tls, struct sockaddr_in6 *addr, int is_primary,
int settopeer, int is_ours)`.  

`is_primary` sets this address as the default. `settopeer` tells TCPLS
to announce this address to the peer. If this connection is a
server-side connection, and if this function is called before the
hanshake, then TCPLS will send this address as part of a new
EncryptedExtension. The client application is advertised of the new
address through an connection event mechanism that we will discuss below.  

If this function called before the handshake and the connection is
client-side, then the information will be sent as part of the first data
sent during this connection. This restriction is designed to avoid
making more entropy for fingerprinting, avoiding the client-side handshake to look
different depending on the number of encrypted addresses advertized.  

If these functions nare called after the handshake, then the application
can either call `tcpls_send_addresses` to send addresses right away or
wait the next exchange of application-level data, in which new addresses
will be also included.

### Connecting with multiple addresses

picotcpls provides `tcpls_connect(ptls_t *tls, struct sockaddr *src,
struct sockaddr *dest, struct timeval *timeout)` to make TCP connections
to the server. The bi-partite graph connection can be made explicit by
calling several times `tcpls_connect`. For
example, assuming that both the client and the server have a v4 and v6:  

```
tcpls_connect(tls, src_v4, dest_v4, NULL);
tcpls_connect(tls, src_v6, dest_v6, timeout);
```
spawns two TCP connections between the two pairs of addresses, for which
the second `tcpls_connect` waits until all connected or the timeout
fired. TCPLS monitors at which speed those connection connected and
automatically set as primary the one that connected the faster.
Callbacks events are triggered when a connection succeeded, and the
application may know which addresses are usable to attach streams, and
which ones require to call tcpls_connect again in case the timeout fired.

Note that this design allows the application to implement various
connectivity policies, such as happy eyeball with a `timeout1` of 50ms:

```
if (tcpls_connect(tls, src_v4, dest_v4, timeout1) > 0)
   tcpls_connect(tls, src_v6, dest_v6, timeout2);
```
This code instructs TCPLS to connect to the IPv4 and use it if the
connection is successful under 50ms. If it is not, it tries the v6 and
then set as primary the fastest of the two (assuming both connected in
the second call).  

Setting src and dest to `NULL` would make tcpls_connect tries a full
mesh TCP connections between all addresses added with `tcpls_add_v4` and `tcpls_add_v6`.  
Setting only src to `NULL` makes tcpls_connect uses the default system's
routing rules to select a src address.

New connections can be made at any time of the initial connection
lifetime and may offer to the application an easy interface to program
failback mechanism (or let TCPLS automatically handle failback) or
aggregation of bandwidth with multipathing.

### Handshake

picotcpls simply offer a wrapper around picotls's `ptls_handshake`:  

`tcpls_handshake(ptls_t *tls);`

this function waits until the handshake is complete or an error occured.
It may also triggers various callbacks depending on events occuring in
the handshake.

### Adding / closing streams

### Sending / receiving data

### Handling events

Using the cli command
---

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

The software is provided under the MIT license.
Note that additional licences apply if you use the minicrypto binding (see above).
