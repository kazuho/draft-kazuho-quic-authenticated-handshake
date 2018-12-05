---
title: Authenticated Handshake for QUIC
docname: draft-kazuho-quic-authenticated-handshake-latest
category: exp

ipr: trust200902
area: Transport
workgroup: quic
keyword: Internet-Draft

stand_alone: yes
pi: [toc, docindent, sortrefs, symrefs, strict, compact, comments, inline]

author:
  -
    ins: K. Oku
    name: Kazuho Oku
    org: Fastly
    email: kazuhooku@gmail.com

normative:
  RFC2119:
  RFC8446:
  QUIC-TRANSPORT:
    title: "QUIC: A UDP-Based Multiplexed and Secure Transport"
    seriesinfo:
      Internet-Draft: draft-ietf-quic-transport-latest
    author:
      -
        ins: J. Iyengar
        name: Jana Iyengar
        org: Fastly
        role: editor
      -
        ins: M. Thomson
        name: Martin Thomson
        org: Mozilla
        role: editor
  QUIC-TLS:
    title: "Using Transport Layer Security (TLS) to Secure QUIC"
    seriesinfo:
      Internet-Draft: draft-ietf-quic-tls-latest
    author:
      -
        ins: M. Thomson
        name: Martin Thomson
        org: Mozilla
        role: editor
      -
        ins: S. Turner
        name: Sean Turner
        org: sn3rd
        role: editor
  TLS-ESNI:
    title: Encrypted Server Name Indication for TLS 1.3
    seriesinfo:
      Internet-Draft: draft-ietf-tls-esni-latest
    author:
      -
        ins: E. Rescorla
        name: Eric Rescorla
        org: RTFM, Inc.
      -
        ins: K. Oku
        name: Kazuho Oku
        org: Fastly
      -
        ins: N. Sullivan
        name: Nick Sullivan
        org: Cloudflare
      -
        ins: C. A. Wood
        name: Christopher A. Wood
        org: Apple, Inc.

informative:

--- abstract

This document explains a variant of QUIC protocol version 1 that uses the ESNI
Keys to authenticate the Initial packets thereby making the entire handshake
tamper-proof.

--- middle

# Introduction

As defined in Secure Using TLS to Secure QUIC [QUIC-TLS], QUIC version 1
[QUIC-TRANSPORT] protects the payload of every QUIC packet using AEAD making
the protocol injection- and tamper-proof, with the exception being the Initial
packets.  Initial packets are merely obfuscated because there is no shared
secret between the endpoints when they start sending the Initial packets
against each other.

However, when Encrypted Server Name Indication for TLS 1.3 [TLS-ESNI] is used,
a shared secret between the endpoints can be used for authentication from the
very first packet of the connection.

This document introduces an additional authenticated data (AAD) construction
that includes a secret value derived from the ESNI shared secret so that third
parties cannot inject or alter the packets.

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC2119].

# Protocol Version Number

The long header packets exchanged using this specification carry the QUIC
version number of 0xXXXXXXXX (TBD).

# The "QUIC-ESNI" TLS Extension

The QUIC-ESNI TLS Extension indicates the server-supported QUIC versions that
use the Encrypted SNI exntension in a way that affects the QUIC transport
layer.

~~~
   struct {
       uint32 supported_versions<4..2^16-4>;
   } QUIC_ESNI;
~~~

A server willing to accept QUIC connections using this specification MUST
publish ESNI Resource Records that contain the QUIC_ESNI extension including
the QUIC version number 0xXXXXXXXX.

A client MUST NOT initiate a connection establishment attempt specified in
this document unless it sees a compatible version number in the QUIC_ESNI
extension of the ESNI Resource Record advertised by the server.

# Construction of Authenticated Additional Data

QUIC version 1 uses the packet header as the AAD input of the packet
protection.  In this variant, the AAD used for the Initial packet is an
concatenation of the packet header and an authentication secret that is
derived from the shared ESNI secret using the following computation:

~~~
   initial_auth_secret = HKDF-Expand-Label(Zx, "quic initial auth",
                                           Hash(ESNIContents), 16)
~~~

AAD for other types of packets are identical to that of QUIC version 1.

# Handling of Version Negotiation Packet

A client MUST ignore a Version Negotiation packet received in response.  When
the client gives up of establishing a connection, it MAY report the failure
differently based on the receipt of (or lack of) Version Negotiation packets.

# Considerations

## Abnormal Use of AEAD cipher

The design principle of AEAD is to provide authentication and encryption as a
single function.

The proposed approach goes against the principle. A server is expected to
decrypt the packet payload, derive the shared ESNI secret and the Initial
packet authentication secret from the contained Client Hello message, then
validate the AEAD tag.

We can consider using AES-CTR for encryption and HMAC for authentication. Use
of a hash function that is selected by the ESNI key exchange can be considered
to be more generic than relying on GCM for authentication.  The flip side is
that it would be a bigger diversion from QUIC version 1.

We can also consider adding a small checksum to the Initial packets so that
the server can determine if the packet is corrupt. The downside is that the
endpoints would be required to calculate the checksum for Initial packets that
carry server's messages and ACKs as well, even though the correctness of the
packet can be verified using the ordinary procedure of AEAD.

## Use of Different QUIC Version Number

For this specification, use of a different QUIC version number is not expected
to have negative impact on user-experience by raising the chance of version
negotiation, because version negotiation finishes before the client sends it's
first packet.

Use of Encrypted SNI will stick out more, because version number is an
unobfuscated field that exists at the front of the packet.

# Security Considerations

TBD

# IANA Considerations

TBD

# Acknowledgements

TBD
