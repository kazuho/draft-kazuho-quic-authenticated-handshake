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
  -
    ins: C. Huitema
    name: Christian Huitema
    org: Private Octopus Inc.
    email: huitema@huitema.net

normative:
  RFC2104:
  RFC2119:
  RFC8446:
  QUIC-TRANSPORT:
    title: "QUIC: A UDP-Based Multiplexed and Secure Transport"
    seriesinfo:
      Internet-Draft: draft-ietf-quic-transport-16
    date: 2018-10-23
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
      Internet-Draft: draft-ietf-quic-tls-16
    date: 2018-10-23
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
      Internet-Draft: draft-ietf-tls-esni-02
    date: 2018-10-22
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
key is calculated using the following formula, where Zx is the extracted DH
shared secret of Encrypted SNI:

~~~
   hmac_key = HKDF-Expand-Label(Zx, "quic initial auth", Hash(ESNIContents),
                                digest_size)
~~~

The first sixteen (16) octets of the HMAC output replaces the authentication
tag of QUIC version 1.

Other types of packets are protected using the Packet Protection method
defined in QUIC version 1.

### Destination Connection ID

When establishing a connection, a client MUST initially set the Destination
Connection ID to the hashed value of the first payload of the CRYPTO stream
(i.e., the ClientHello message) truncated to first sixteen (16) bytes.  The
hash function being used is the one selected by Encrypted SNI.

When processing the first payload carried by a CRYPTO stream, a server MUST,
in addition to verifying the authentication tag, verify that the truncated
hash value of the payload is identical to the Destination Connection ID or to
the original Connection ID recovered from the the Retry Token.  A server MUST
NOT create or modify connection state if either or both the verification
fails.

## Version Negotiation Packet

A client MUST ignore Version Negotiation packets.  When the client gives up of
establishing a connection, it MAY report the failure differently based on the
receipt of (or lack of) Version Negotiation packets.

## Connection Close Packet

A Connection Close packet shares a long packet header with a type value of 0x3
with the Retry packet.  The two types of packets are identified by the lower
4-bits of the first octet.  The packet is a Connection Close packet if all the
bits are set to zero.  Otherwise, the packet is a Retry packet.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|1| 3 |   0   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|DCIL(4)|SCIL(4)|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0/32..144)         ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Source Connection ID (0/32..144)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Error Code (16)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
(: #connection-close-format title="Connection Close Packet")

A Connection Close packet is sent by a server when a connection error occurs
prior to deriving the HMAC key.  In all other conditions, connection close
MUST be signalled using the CONNECTION_CLOSE frame.

A client that receives a Connection Close packet before an Initial packet
SHOULD retain the error code, and continue the connection establishment
attempt as if it did not see the packet.  When the attempt times out, it MAY
assume that the error code was a legitimate value sent by the server.  A
client MAY ignore Connection Close packets.

## Retry Packet

A client SHOULD send one Initial packet in response to each Retry packet it
receives.  The Destination Connection ID of the Initial packet MUST be set to
the value specified by the Retry packet, however the keys for encrypting and
authenticating the packet MUST continue to be the original ones.  A server
sending a Retry packet is expected to include the original Connection ID in
the Retry Token it emits, and to use the value contained in the token attached
to the Initial packet for unprotecting the payload.

Payload of the CRYPTO frame contained in the resent Initial packets MUST be
identical to that of the Initial packet that triggered the retry.

When the client does not receive a valid Initial packet after a handshake
timeout, it SHOULD send an Initial packet with the Destination Connection ID
and the token set to the original value.

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

Use of Encrypted SNI will stick out more, because it can be identified by
observing a different version number in the long header packet rather than by
decrypting the Initial packet to see if the Encrypted SNI extension is in use.

The subsections below discuss alternative approaches that do not change the
version number of QUIC.

### Trial Decryption

It is possible to use the proposed Packet Protection method without changing
the version number.  The difference from the recommended method is that the
server would be required to do "trial decryption."

However, it is not as bad as it sounds, because authentication failure in
AES-GCM decryption is typically reported after the ciphertext is decrypted.

When accepting a new connection, a QUIC server can at first decrypt the
Initial packet using AES-GCM.  The packet is a ordinary QUIC version 1 packet
if it is successfully authenticated.  Otherwise, the server will feed the
decrypted payload (which would be available anyways) assuming that it contains
a ClientHello message, and if the TLS stack successfully processes the message
returning the handshake keys and the ESNI shared key, verify the HMAC to see
if the packet authenticates.  If it does, the server creates a new connection
context and responds with an Initial packet.

### Rekeying at the Server's First Flight

Another approach is to use the Packet Protection method of QUIC version 1 for
client's first flight, while using the proposed method for all other Initial
packets.

The benefit of this approach is that trial decryption can be avoided.

The downside is that a man-on-the-side attacker can stitch the Encrypted SNI
extension that the client has sent with anything it wants to construct a
spoofed packet, then race it to the server.

The server would be required to consider Initial packets containing
non-identical ClientHello messages as belonging to different connection
establishment attempts.

The design will also have negative performance impact on connections with high
latency.  This is because QUIC expects clients to retransmit the Initial
packets when the latency is above 250 milliseconds.  However, the requirement
that the server rekeys the Initial secret when receiving the first Initial
packet means that the retransmitted Initial packets would become undecryptable
and therefore be deemed lost by the client, reducing the client's congestion
window size.

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

--- back

# Acknowledgements

TBD

# Change Log

## Since draft-kazuho-quic-authenticated-handshake-00

* None yet.
