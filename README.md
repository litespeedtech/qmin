# QMIN: Header Compression for QUIC

QMIN is a compression format and protocol for HTTP/2 headers.  QMIN is
based on HPACK.  The modifications to HPACK are meant to allow robust
compression use in QUIC:  That is, no head-of-line blocking and low
overhead.  QMIN is guided by HPACK design principles.  It inherits all
of HPACK's data structures and retains binary compatibility with it.
While designed with QUIC in mind, QMIN can be used in other contexts.

## What's Here

- [QMIN Internet Draft](id-qmin.txt)
- [QMIN Implementation](src)
- [QMIN Encoder State Diagrams](https://rawgit.com/litespeedtech/qmin/master/doc/enc-diag/qmin-encoder.html)
