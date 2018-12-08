---
title: Authenticated Handshake for QUIC
docname: draft-kazuho-quic-authenticated-handshake-latest
category: exp

ipr: trust200902
area: Transport
workgroup: QUIC
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
  RFC2104:
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

This document defines a Packet Protection method for Initial packets that
incorporates the ESNI shared secret, so that spoofed Initial packets will be
detected and droped.

## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC2119].

# Differences from QUIC version 1

The document describes the changes from QUIC version 1.

Implementations MUST conform to the specifications of QUIC version 1 unless a
different behavior is defined in this document.

## Protocol Version Number

The long header packets exchanged using this specification carry the QUIC
version number of 0xXXXXXXXX (TBD).

## The "QUIC-ESNI" TLS Extension

The QUIC-ESNI TLS Extension indicates the versions of the QUIC protocol that
the server supports.  The values in the extension SHOULD be identical to what
would be included in the Version Negotiation packet.

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

## Initial Packet Protection

Initial packets are encrypted and authenticated differently from QUIC version
1.

AES {{!AES=DOI.10.6028/NIST.FIPS.197}} in counter (CTR) mode is used for
encrypting the payload.  The key and iv being used are identical to that of
QUIC version 1.

HMAC [RFC2104] is used for authenticating the header.  The message being
authenticated is the concatenation of the packet header without Header
Protection and the payload in cleartext.  The underlying hash function being
used is the one selected for encrypting the Encrypted SNI extension.  The HMAC
key is calculated using the following formula:

~~~
   hmac_key = HKDF-Expand-Label(Zx, "quic initial auth", Hash(ESNIContents),
                                digest_size)
~~~

The first sixteen (16) octets of the HMAC output replaces the authentication
tag of QUIC version 1.

Other types of packets are protected using the Packet Protection method
defined in QUIC version 1.

## Version Negotiation Packet

A client MUST ignore Version Negotiation packets.  When the client gives up of
establishing a connection, it MAY report the failure differently based on the
receipt of (or lack of) Version Negotiation packets.

## Retry Packet

A client SHOULD send an Initial packet in response to each Retry packet it
receives.  Payload of the CRYPTO frame contained in the resent Initial packets
MUST be identical to that of the Initial packet that triggered the retry.
When the client does not receive a valid Initial packet after a handshake
timeout, it SHOULD send at least one Initial packet containing one of the
tokens that it has received.  Unless the packet gets lost, the retransmission
would trigger the server to send either a valid Initial packet or a Retry
packet.

To a server, the behavior of a client under attack would look like it is
aggressively retransmitting Initial packets, some of them containing invalid
tokens.

Therefore, a server MUST NOT terminate the connection when it receives an
Initial packet that contains an invalid token.  Instead, it SHOULD either
process the packet as if it did not contain a token, or send a Retry.

A client MUST ignore Retry packets received anterior to an Initial packet that
successfully authenticates.

# Considerations

## Using GCM to Authenticate Initial Packets

An alternative approach to using the combination of AES-CTR and HMAC is to
continue using AES-GCM.  In such approach, the additional authenticated data
(AAD) will incorporate the ESNI shared secret to detect spoofed or broken
packets.

A server that receives an Initial packet for a new connection will at first
decrypt the payload using AES-CTR, derive ESNI shared secret from the Hello
message being contained, then use that to verify the GCM tag.

The benefit of the approach is that we will have less divergence from QUIC
version 1.  The downside is that the authentication algorithm would be
hard-coded to GCM, and that some AEAD APIs might not provide an interface to
handle input in this particular way.

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

## No Support for Split Mode

Under the design discussed in this document, it is impossible to use an
unmodified QUIC server as a backend server in "Split Mode" ([TLS-ESNI];
section 3) due to the following two reasons:

* Access to initial_auth_secret is required for generating and validating
  Initial packets.  However, the backend server, not knowing the ESNI private
  key, cannot calculate the secret.

* The client-facing server cannot continue forwarding packets to the correct
  destination when there is a change in Connection ID mid-connection.

To address the issues, we might consider specifying a protocol that will be
used between the client-facing server and the backend server for communicating
the initial_auth_secret and the spare Connection IDs.  Note that such protocol
can be lightweight, assuming the communication between the two servers will be
over a virtual private network.  Such assumption can be made because the
backend server cannot operate QUIC without access to the source address-port
tuple of the packets that the client has sent.

# Security Considerations

TBD

# IANA Considerations

TBD

# Acknowledgements

TBD
