%%%
title = "Native JWT Representation of Verifiable Credentials"
abbrev = "jwt-vcs"
ipr= "trust200902"
area = "Internet"
workgroup = "None"
submissiontype = "IETF"
keyword = ["JOSE","COSE","JWT","CWT"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-prorock-oauth-jwt-vcs-latest"
stream = "IETF"
status = "standard"

[pi]
toc = "yes"

[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="Authlete Inc. "
    [author.address]
    email = "mail@danielfett.de"

[[author]]
initials = "M."
surname = "Prorock"
fullname = "Michael Prorock"
organization = "mesur.io"
  [author.address]
  email = "mprorock@mesur.io"

[[author]]
initials = "O."
surname = "Steele"
fullname = "Orie Steele"
organization = "Transmute"
  [author.address]
  email = "orie@transmute.industries"

[[author]]
initials="O."
surname="Terbu"
fullname="Oliver Terbu"
organization="Spruce Systems, Inc."
    [author.address]
    email = "oliver.terbu@spruceid.com"


%%%

.# Abstract

This document describes how to construct and utilize
a JWT as a Verifiable Credential utilizing only JSON
and registered claims. This document also covers use
of SD-JWTs as a verifiable Credentials.

This document does not define any new cryptography,
only seralizations of systems.


{mainmatter}

# Notational Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**",
"**SHOULD NOT**", "**RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this
document are to be interpreted as described in [@!RFC2119].

# Terminology

The following terminology is used throughout this document:

This specification uses the terms "Holder", "Issuer", "Verifier",
defined by [@!I-D.ietf-oauth-selective-disclosure-jwt].

signature
: The digital signature output.

Verifiable Credential (VC):
:  An Issuer-signed assertion with claims about a Subject.

SD-JWT-based Verifiable Credential (SD-JWT VC):
: A Verifiable Credential encoded using the Issuance format defined in
[@!I-D.ietf-oauth-selective-disclosure-jwt].

Unsecured payload of an SD-JWT VC:
: A JSON object containing all selectively disclosable and
non-selectively disclosable claims of the SD-JWT VC. The unsecured
payload acts as the input JSON object to issue an SD-JWT VC complying to
this specification.

Status Provider:
: An entity that provides status information (e.g. revocation) about a
Verifiable Credential.

# Scope

* This specification defines
  * Data model and media types for Verifiable Credentials based on JWTs
    and SD-JWTs.
  * Validation and processing rules for Verifiers and Holders.

# Introduction

## Three-Party-Model

In the so-called Three-Party-Model, Issuers issue Verifiable Credentials to a
Holder, who can then present the Verifiable Credentials to Verifiers. Verifiable
Credentials are cryptographically signed statements about a Subject, typically the Holder.

~~~ ascii-art
         +------------+
         |            |
         |   Issuer   |
         |            |
         +------------+
               |
    Issues Verifiable Credential
               |
               v
         +------------+
         |            |
         |   Holder   |
         |            |
         +------------+
               |
  Presents Verifiable Credential
               |
               v
         +-------------+
         |             |+                          +------------+
         |  Verifiers  ||+                         |   Status   |
         |             |||----- optionally ------->|  Provider  |
         +-------------+||   retrieve status of    |            |
          +-------------+|  Verifiable Credential  +------------+
           +-------------+
~~~

Figure: Three-Party-Model with optional Status Provider

Verifiers can check the authenticity of the data in the Verifiable
Credentials and optionally enforce Holder Binding, i.e., ask the Holder
to prove that they are the intended holder of the Verifiable Credential,
for example, by proving possession of a cryptographic key referenced in
the credential. This process is further described in
[@!I-D.ietf-oauth-selective-disclosure-jwt].

To support revocation of Verifiable Credentials, an optional fourth
party can be involved, a Status Provider, who delivers revocation
information to Verifiers. (The Verifier can also serve as the Status
Provider.)

This specification defines Verifiable Credentials based on the SD-JWT
format with a JWT Claim Set.

## Rationale

JSON Web Tokens (JWTs) [@!RFC7519] can in principle be used to express
Verifiable Credentials in a way that is easy to understand and process
as it builds upon established web primitives. While JWT-based
credentials enable selective disclosure, i.e., the ability for a Holder
to disclose only a subset of the contained claims, in an Identity
Provider ecosystem by issuing new JWTs to the Verifier for every
presentation, this approach does not work in the three-party-model.

Selective Disclosure JWT (SD-JWT)
[@!I-D.ietf-oauth-selective-disclosure-jwt] is a specification that
introduces conventions to support selective disclosure for JWTs: For an
SD-JWT document, a Holder can decide which claims to release (within
bounds defined by the Issuer). This format is therefore perfectly suited
for Verifiable Credentials.

SD-JWT itself does not define the claims that must be used within the
payload or their semantics. This specification therefore defines how
Verifiable Credentials can be expressed using SD-JWT.

JWTs (and SD-JWTs) can contain claims that are registered in "JSON Web
Token Claims" registry as defined in [@!RFC7519], as well as public and
private claims. Private claims are not relevant for this specification
due to the openness of the three-party-model. Since SD-JWTs are based on
JWTs, this specification aims to express the basic Verifiable Credential
data model purely through JWT Claim Sets, using registered claims while
allowing Issuers to use additional registered claims, as well as new or
existing public claims, to make statements about the Subject of the
Verifiable Credential.

# Native JWT Representation of Verifiable Credentials

## Overview

This section provides guidance on how to use JSON [@!RFC8259] claimsets
with JWT [@!RFC7519] registered claims to construct a JWT that can be
mapped to a verifiable credential. This section also describes how to
use content types and token types to distinguish different
representations of verifiable credentials.

This representation relies on claims registered in the [IANA JSON Web
Token Claims
Registry](https://www.iana.org/assignments/jwt/jwt.xhtml#claims)
whenever possible.

Implementers using this representation SHOULD NOT use `vc+ld+json` as an
input.

### Credential Header

`typ` MUST use the media type `vc+jwt`.

Example of credential metadata (decoded JWT header):

```json
{
  "kid": "https://example.edu/issuers/14#key-0",
  "alg": "ES256",
  "typ": "vc+jwt"
}
```

### Credential

Example of a credential (decoded JWT payload):

```json
{
  "iss": "https://example.edu/issuers/14",
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "urn:example:claim": true
}
```

NOTE: The `vc` and `vp` claims MUST NOT be present when the content
type header parameter is set to `credential-claims-set+json`.

### Verifiable Credential

Example of an JWT encoded verifiable credential (using external proof):

```json
=============== NOTE: '\' line wrapping per RFC 8792 ================
eyJraWQiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvMTQja2V5LTAiLCJhbGci\
OiJFUzI1NiIsInR5cCI6InZjK2p3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR\
1L2lzc3VlcnMvMTQiLCJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiw\
iaWF0IjoxNTE2MjM5MDIyLCJ1cm46ZXhhbXBsZTpjbGFpbSI6dHJ1ZX0.WLD4Qxh629T\
FkJHzmbkWEefYX-QPkdCmxbBMKNHErxND2QpjVBbatxHkxS9Y_SzBmwffuM2E9i5VvVg\
pZ6v4Tg
```

# Verifiable Credentials based on SD-JWT

This section defines encoding, validation and processing rules for SD-JWT VCs.

## Media Type

SD-JWT VCs compliant with this specification MUST use the media type
`application/vc+sd-jwt` as defined in (#application-vc-sd-jwt).

## Data Format

SD-JWT VCs MUST be encoded using the SD-JWT Combined Format for Issuance as
defined in Section 5.3. of [@!I-D.ietf-oauth-selective-disclosure-jwt].

SD-JWT VCs MUST contain all Disclosures corresponding to their SD-JWT component
except for Decoy Digests as per Section 5.1.1.3. of [@!I-D.ietf-oauth-selective-disclosure-jwt].

### Header Parameters

This section defines JWT header parameters for the SD-JWT component of the
SD-JWT VC.

The `typ` header parameter of the SD-JWT MUST be present. The `typ` value MUST
use `vc+sd-jwt`. This indicates that the payload of the SD-JWT contains plain
JSON and follows the rules as defined in this specification. It further
indicates that the SD-JWT is a SD-JWT component of a SD-JWT VC.

The following is a non-normative example of a decoded SD-JWT header:

```
{
  "alg": "ES256",
  "typ": "vc+sd-jwt"
}
```

### Claims

This section defines the claims that can be included in the payload of
SD-JWT VCs.

#### `type` claim {#type-claim}

This specification defines the JWT claim `type`. The `type` claim is used
to express the type of the JSON object that is secured by the
JWT. The `type` value MUST be a case-sensitive `StringOrURI` value.

The following is a non-normative example of how `type` is used to express
a type:

```
{
  "type": "SomeType"
}
```

#### Registered JWT Claims

SD-JWT VCs MAY use any claim registered in the "JSON Web Token Claims"
registry as defined in [@!RFC7519].

If present, the following registered JWT claims MUST be included in the SD-JWT
and MUST NOT be included in the Disclosures, i.e. cannot be selectively
disclosed:

* `iss`
    * REQUIRED. The Issuer of the Verifiable Credential. The value of `iss`
MUST be a URI. See [@!RFC7519] for more information.
* `iat`
    * REQUIRED. The time of issuance of the Verifiable Credential. See
[@!RFC7519] for more information.
* `nbf`
    * OPTIONAL. The time before which the Verifiable Credential MUST NOT be
accepted before validating. See [@!RFC7519] for more information.
* `exp`
    * OPTIONAL. The expiry time of the Verifiable Credential after which the
Verifiable Credential is no longer valid. See [@!RFC7519] for more
information.
* `cnf`
    * REQUIRED when Cryptographic Holder Binding is to be supported. Contains the confirmation method as defined in [@!RFC7800]. It SHOULD contain a JWK as defined in Section 3.2 of [@!RFC7800] and in this case, the `kid` (Key ID) member MUST be present in the JWK.  For Cryptographic Holder Binding, the Holder Binding JWT in the Combined Format for Presentation MUST be signed by the key identified in this claim.
* `type`
    * REQUIRED. The type of the Verifiable Credential, e.g.,
`IdentityCredential`, as defined in (#type-claim).
* `status`
    * OPTIONAL. The information on how to read the status of the Verifiable
Credential. See [TBD] for more information.

The following registered JWT claims MAY be contained in the SD-JWT or in the
Disclosures and MAY be selectively disclosed:

* `sub`
    * OPTIONAL. The identifier of the Subject of the Verifiable Credential.
The value of `sub` MUST be a URI. The Issuer MAY use it to provide the Subject
identifier known by the Issuer. There is no requirement for a binding to
exist between `sub` and `cnf` claims.

#### Public JWT claims

Additional public claims MAY be used in SD-JWT VCs depending on the
application.

## Example

The following is a non-normative example of an unsecured payload of an
SD-JWT VC.

```
{
  "type": "IdentityCredential",
  "given_name": "John",
  "family_name": "Doe",
  "email": "johndoe@example.com",
  "phone_number": "+1-202-555-0101",
  "address": {
    "street_address": "123 Main St",
    "locality": "Anytown",
    "region": "Anystate",
    "country": "US"
  },
  "birthdate": "1940-01-01",
  "is_over_18": true,
  "is_over_21": true,
  "is_over_65": true
}
```

The following is a non-normative example of how the unsecured payload of the
SD-JWT VC above can be used in a SD-JWT where the resulting SD-JWT VC contains
only claims about the Subject that are selectively disclosable:

```
{
  "_sd": [
    "09vKrJMOlyTWM0sjpu_pdOBVBQ2M1y3KhpH515nXkpY",
    "2rsjGbaC0ky8mT0pJrPioWTq0_daw1sX76poUlgCwbI",
    "EkO8dhW0dHEJbvUHlE_VCeuC9uRELOieLZhh7XbUTtA",
    "IlDzIKeiZdDwpqpK6ZfbyphFvz5FgnWa-sN6wqQXCiw",
    "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
    "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
    "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
    "jdrTE8YcbY4EifugihiAe_BPekxJQZICeiUQwY9QqxI",
    "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
  ],
  "iss": "https://example.com/issuer",
  "iat": 1683000000,
  "exp": 1883000000,
  "type": "IdentityCredential",
  "_sd_alg": "sha-256",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
      "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    }
  }
}
```

Note that a `cnf` claim has been added to the SD-JWT payload to express the
confirmation method of the holder binding.

The following are the Disclosures belonging to the SD-JWT payload above:

Claim given_name:

* SHA-256 Hash: jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4
* Disclosure:
WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
* Contents: ["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]

Claim family_name:

* SHA-256 Hash: TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo
* Disclosure:
WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd
* Contents: ["eluV5Og3gSNII8EYnsxA_A", "family_name", "Doe"]

Claim email:

* SHA-256 Hash: JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE
* Disclosure:
WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VA
ZXhhbXBsZS5jb20iXQ
* Contents: ["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]

Claim phone_number:

* SHA-256 Hash: PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI
* Disclosure:
WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgInBob25lX251bWJlciIsICIr
MS0yMDItNTU1LTAxMDEiXQ
* Contents: ["eI8ZWm9QnKPpNPeNenHdhQ", "phone_number",
"+1-202-555-0101"]

Claim address:

* SHA-256 Hash: IlDzIKeiZdDwpqpK6ZfbyphFvz5FgnWa-sN6wqQXCiw
* Disclosure:
WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVl
dF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRv
d24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0
* Contents: ["Qg_O64zqAxe412a108iroA", "address", {"street_address":
"123 Main St", "locality": "Anytown", "region": "Anystate", "country":
"US"}]

Claim birthdate:

* SHA-256 Hash: jdrTE8YcbY4EifugihiAe_BPekxJQZICeiUQwY9QqxI
* Disclosure:
WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0
* Contents: ["AJx-095VPrpTtN4QMOqROA", "birthdate", "1940-01-01"]

Claim is_over_18:

* SHA-256 Hash: 09vKrJMOlyTWM0sjpu_pdOBVBQ2M1y3KhpH515nXkpY
* Disclosure:
WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImlzX292ZXJfMTgiLCB0cnVlXQ
* Contents: ["Pc33JM2LchcU_lHggv_ufQ", "is_over_18", true]

Claim is_over_21:

* SHA-256 Hash: 2rsjGbaC0ky8mT0pJrPioWTq0_daw1sX76poUlgCwbI
* Disclosure:
WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImlzX292ZXJfMjEiLCB0cnVlXQ
* Contents: ["G02NSrQfjFXQ7Io09syajA", "is_over_21", true]

Claim is_over_65:

* SHA-256 Hash: EkO8dhW0dHEJbvUHlE_VCeuC9uRELOieLZhh7XbUTtA
* Disclosure:
WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlzX292ZXJfNjUiLCB0cnVlXQ
* Contents: ["lklxF5jMYlGTPUovMNIvCA", "is_over_65", true]

The SD-JWT and the Disclosures would then be serialized by the Issuer into the following format for issuance to the Holder:

```
eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CV
kJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kY
Xcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZ
UxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNON
ndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQW
WxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJI
iwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAia
mRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5e
VZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAia
HR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4c
CI6IDE4ODMwMDAwMDAsICJ0eXBlIjogIklkZW50aXR5Q3JlZGVudGlhbCIsICJfc2RfY
WxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiO
iAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsc
zd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2d
DRqVDlGMkhaUSJ9fX0.7-uYweCWRwFrKmcv1sqd3HFMd5Tn1PcytgarFfO7k-L0uSo-M
WXmU-RjekKFblomzevP-6w8rNZ2sIo7f5D7fw~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STj
l3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BI
iwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwg
ImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlSThaV205UW5LUHBOUGVOZ
W5IZGhRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ~WyJRZ19PNj
R6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIj
EyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueX
N0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIi
wgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0~WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdW
ZRIiwgImlzX292ZXJfMTgiLCB0cnVlXQ~WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiw
gImlzX292ZXJfMjEiLCB0cnVlXQ~WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImlz
X292ZXJfNjUiLCB0cnVlXQ
```

## Verification and Processing {#vc-sd-jwt-verification-and-processing}

The recipient of the SD-JWT VC MUST process and verify an SD-JWT VC as
follows:

 1. REQUIRED. Process and verify the SD-JWT as defined in
Section 6. of [@!I-D.ietf-oauth-selective-disclosure-jwt]. For the
verification, the `iss` claim in the SD-JWT MAY be used to retrieve the public
key from the JWT Issuer Metadata configuration (as defined in
(#jwt-issuer-metadata)) of the SD-JWT VC issuer. A Verifier MAY use alternative
methods to obtain the public key to verify the signature of the SD-JWT.
 1. OPTIONAL. If `status` is present in the verified payload of the SD-JWT,
the status SHOULD be checked. It depends on the Verifier policy to reject or
accept a presentation of a SD-JWT VC based on the status of the Verifiable
Credential.

Any claims used that are not understood MUST be ignored.

Additional validation rules MAY apply, but their use is out of the scope of
this specification.

# JWT Issuer Metadata {#jwt-issuer-metadata}

This specification defines the JWT Issuer Metadata to retrieve the JWT Issuer
Metadata configuration of the JWT Issuer of the JWT. The JWT Issuer is
identified by the `iss` claim in the JWT. Use of the JWT Issuer Metadata
is OPTIONAL.

JWT Issuers publishing JWT Issuer Metadata MUST make a JWT Issuer Metadata
configuration available at the path formed by concatenating the string
`/.well-known/jwt-issuer` to the `iss` claim value in the JWT. The `iss` MUST
be a case-sensitive URL using the HTTPS scheme that contains scheme, host and,
optionally, port number and path components, but no query or fragment
components.

## JWT Issuer Metadata Request

A JWT Issuer Metadata configuration MUST be queried using an HTTP `GET` request
at the path defined in (#jwt-issuer-metadata).

The following is a non-normative example of a HTTP request for the JWT Issuer
Metadata configuration when `iss` is set to `https://example.com`:

```
GET /.well-known/jwt-issuer HTTP/1.1
Host: example.com
```

If the `iss` value contains a path component, any terminating `/` MUST be
removed before inserting `/.well-known/` and the well-known URI suffix
between the host component and the path component.

The following is a non-normative example of a HTTP request for the JWT Issuer
Metadata configuration when `iss` is set to `https://example.com/user/1234`:

```
GET /.well-known/jwt-issuer/user/1234 HTTP/1.1
Host: example.com
```

## JWT Issuer Metadata Response

A successful response MUST use the `200 OK HTTP` and return the JWT Issuer
Metadata configuration using the `application/json` content type.

An error response uses the applicable HTTP status code value.

This specification defines the following JWT Issuer Metadata configuration
parameters:

* `issuer`
      REQUIRED. The JWT Issuer identifier, which MUST be identical to the `iss`
value in the JWT.
* `jwks_uri`
    * OPTIONAL. URL string referencing the JWT Issuer's JSON Web Key (JWK) Set
[@RFC7517] document which contains the JWT Issuer's public keys. The value of
this field MUST point to a valid JWK Set document. Use of this parameter is
RECOMMENDED, as it allows for easy key rotation.
* `jwks`
    * OPTIONAL. JWT Issuer's JSON Web Key Set [@RFC7517] document value, which
contains the JWT Issuer's public keys. The value of this field MUST be a JSON
object containing a valid JWK Set. This parameter is intended to be used by JWT
Issuer that cannot use the `jwks_uri` parameter.

JWT Issuer Metadata MUST include either `jwks_uri` or `jwks` in their JWT
Issuer Metadata, but not both.

It is RECOMMENDED that the JWT contains a `kid` JWT header parameter that can
be used to lookup the public key in the JWK Set included by value or referenced
in the JWT Issuer Metadata.

The following is a non-normative example of a JWT Issuer Metadata configuration
including `jwks`:

```
{
   "issuer":"https://example.com",
   "jwks":{
      "keys":[
         {
            "kid":"doc-signer-05-25-2022",
            "e":"AQAB",
            "n":"nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
   HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
   lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
   RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
   2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
   qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
            "kty":"RSA"
         }
      ]
   }
}
```

The following is a non-normative example of a JWT Issuer Metadata
configuration including `jwks_uri`:

```
{
   "issuer":"https://example.com",
   "jwks_uri":"https://jwt-issuer.example.org/my_public_keys.jwks"
}
```

Additional JWT Issuer Metadata configuration parameters MAY also be used.

## JWT Issuer Metadata Validation

The `issuer` value returned MUST be identical to the `iss` value of the JWT. If
these values are not identical, the data contained in the response MUST NOT be
used.

# Presenting Verifiable Credentials

This section defines encoding, validation and processing rules for presentations
of SD-JWT VCs.

## Data Format

A presentation of an SD-JWT VC MUST be encoded using the SD-JWT Combined
Format for Presentation as defined in Section 5.4. of
[@!I-D.ietf-oauth-selective-disclosure-jwt].

A presentation of an SD-JWT VC MAY contain a Holder Binding JWT as described in
Section 5.4.1. of [@!I-D.ietf-oauth-selective-disclosure-jwt].

### Holder Binding JWT

If the presentation of the SD-JWT VC includes a Holder Binding JWT, the
following claims are used within the Holder Binding JWT:

* `nonce`
    * REQUIRED. String value used to associate a transaction between a Verifier
an a Holder, and to mitigate replay attacks. The value is passed
through unmodified from the Verifier to the Holder Binding JWT. Sufficient
entropy MUST be present in the `nonce` values used to prevent attackers from
guessing values.
* `aud`
    * REQUIRED. The intended recipient of the Holder Binding JWT which is
typically the Verifier. See [@!RFC7519] for more information.
* `iat`
    * REQUIRED. The time of issuance of the Holder Binding JWT. See
[@!RFC7519] for more information.
* `exp`
    * OPTIONAL. The expiration time of the signature when
the Holder Binding is no longer considered valid. See [@!RFC7519]
for more information.

The Holder Binding JWT MAY include addtional claims which when not understood
MUST be ignored.

## Examples

The following is a non-normative example of a presentation of the SD-JWT shown
above including a Holder Binding JWT:

```
eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CV
kJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kY
Xcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZ
UxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNON
ndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQW
WxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJI
iwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAia
mRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5e
VZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAia
HR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4c
CI6IDE4ODMwMDAwMDAsICJ0eXBlIjogIklkZW50aXR5Q3JlZGVudGlhbCIsICJfc2RfY
WxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiO
iAiUC0yNTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsc
zd2Q2VHZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2d
DRqVDlGMkhaUSJ9fX0.7-uYweCWRwFrKmcv1sqd3HFMd5Tn1PcytgarFfO7k-L0uSo-M
WXmU-RjekKFblomzevP-6w8rNZ2sIo7f5D7fw~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm
9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgIm
xvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cn
kiOiAiVVMifV0~eyJhbGciOiAiRVMyNTYifQ.eyJub25jZSI6ICIxMjM0NTY3ODkwIiw
gImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE2ODU
xMDc0NjJ9.LJW9AJ-tnpfaurCo7iaiNI3s37hxz6o5n_RifTtVy1ukqhrQ9GMcKbBhTm
RBhZI6FtQtV5EeuRFXUcDC3-gWeA
```

In this presentation, the Holder provides only the Disclosure for the claim
`address`. Other claims are not disclosed to the Verifier.

The following example shows a presentation of a (different) SD-JWT without a
Holder Binding JWT:

```
eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CV
kJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kY
Xcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZ
UxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNON
ndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQW
WxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJI
iwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAia
mRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5e
VZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAia
HR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4c
CI6IDE4ODMwMDAwMDAsICJ0eXBlIjogIklkZW50aXR5Q3JlZGVudGlhbCIsICJfc2RfY
WxnIjogInNoYS0yNTYifQ.LY36fI1eCB8YgtXogy4yz5nuNk2VIEhOfQ1TZ94WO4wVYR
CRELbwuEmaimAyOU4STmRD4MHo0mdBvzzmPi5Png~WyJRZ19PNjR6cUF4ZTQxMmExMDh
pcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0Iiw
gImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW5
0cnkiOiAiVVMifV0~
```

## Verification and Processing {#vp-sd-jwt-verification-and-processing}

The Verifier MUST process and verify a presentation of SD-JWT VC as follows:

 1. REQUIRED. When processing and verifying the presentation of the SD-JWT VC,
the Verifier MUST follow the same verification and processing rules as defined
in (#vc-sd-jwt-verification-and-processing).
 1. OPTIONAL. If provided, the Verifier MUST verify the Holder Binding JWT
according to Section 6.2. of [@!I-D.ietf-oauth-selective-disclosure-jwt].
To verify the Holder Binding JWT, the `cnf` claim of the SD-JWT MUST be used.

# Security Considerations {#security-considerations}

All security considerations from JSON [@!RFC8259] and JWT [@!RFC7519]
SHOULD be followed.

If utilizing SD-JWTs, all security considerations from SD-JWT
[@!I-D.ietf-oauth-selective-disclosure-jwt] SHOULD be followed.

# IANA Considerations

## JSON Web Token Claims Registration

* Claim Name: "type"
  * Claim Description: Credential Type
  * Change Controller: IESG
  * Specification Document(s): (#type-claim) of this document

## Media Type Registration

### application/vc+jwt

This section will register the "application/vc+jwt" media type [@!RFC2046]
in the "Media Types" registry [IANA.MediaTypes] in the manner described
in RFC 6838 [@!RFC6838], which can be used to indicate that the content is
a JWT.

* Type name: application
* Subtype name: vc+jwt
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: 8bit; JWT values are encoded as a series
  of base64url-encoded values (some of which may be the empty
  string) separated by period ('.') characters.
* Security considerations: See the Security Considerations section
  of RFC 7519
* Interoperability considerations: n/a
* Published specification: n/a
* Applications that use this media type: OpenID Connect, Mozilla
* Persona, Salesforce, Google, Android, Windows Azure, Amazon Web
* Services, and numerous others
* Fragment identifier considerations: n/a
* Additional information:
      Magic number(s): n/a
      File extension(s): n/a
      Macintosh file type code(s): n/a
* Person & email address to contact for further information:
  Michael Prorock, mprorock@mesur.io
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Michael Prorock, mprorock@mesur.io
* Change controller: IESG
* Provisional registration?  Yes

### application/vc+sd-jwt {#application-vc-sd-jwt}

The Internet media type for a SD-JWT VC is `application/vc+sd-jwt`.

* Type name: : `application`
* Subtype name: : `vc+sd-jwt`
* Required parameters: : n/a
* Optional parameters: : n/a
* Encoding considerations: : 8-bit code points; SD-JWT VC values are
  encoded as a series of base64url-encoded values (some of which may be
  the empty string) separated by period ('.') and tilde ('~')
  characters.
* Security considerations: : See Security Considerations in
  (#security-considerations).
* Interoperability considerations: : n/a
* Published specification: : RFC TODO
* Applications that use this media type: Applications that issue,
  present, verify verifiable credentials and presentations.
* Additional information:
  * Magic number(s): n/a
  * File extension(s): n/a
  * Macintosh file type code(s): n/a
  * Person & email address to contact for further information: TBD
  * Intended usage: COMMON
  * Restrictions on usage: none
  * Author: Oliver Terbu <oliver.terbu@spruceid.com>
  * Change controller: IETF

# Acknowledgements {#Acknowledgements}

We would like to thank Michael Jones, Alen Horvat, Andres Uribe,
Christian Bormann, Giuseppe De Marco, Paul Bastian, Torsten Lodderstedt,
Tobias Looker and Kristina Yasuda for their contributions (some of which
substantial) to this draft and to the initial set of implementations.

{backmatter}
