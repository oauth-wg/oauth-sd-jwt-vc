%%%
title = "SD-JWT-based Verifiable Credentials (SD-JWT VC)"
abbrev = "SD-JWT VC"
ipr = "trust200902"
workgroup = "TODO Working Group"
keyword = ["security", "openid", "sd-jwt"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-terbu-sd-jwt-vc-latest"
status = "standard"

[[author]]
initials="O."
surname="Terbu"
fullname="Oliver Terbu"
organization="Spruce Systems, Inc."
    [author.address]
    email = "oliver.terbu@spruceid.com"

[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="Authlete Inc. "
    [author.address]
    email = "mail@danielfett.de"

%%%

.# Abstract

This specification describes data formats as well as validation and processing
rules to express Verifiable Credentials with JSON payloads based on the Selective Disclosure
for JWTs (SD-JWT) [@!I-D.ietf-oauth-selective-disclosure-jwt] format.
It can be used when there are no selective disclosable claims, too.

{mainmatter}

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

Verifiers can check the authenticity of the data in the Verifiable Credentials
and optionally enforce Holder Binding, i.e., ask the Holder to prove that they
are the intended holder of the Verifiable Credential, for example, by proving possession of a
cryptographic key referenced in the credential. This process is further
described in [@!I-D.ietf-oauth-selective-disclosure-jwt].

To support revocation of Verifiable Credentials, revocation information can
optionally be retrieved from a Status Provider. The role of a Status Provider
can be fulfilled by either a fourth party or by the Issuer.

This specification defines Verifiable Credentials based on the SD-JWT
format with a JWT Claim Set. It can be used when there are no selective disclosable claims, too.

## Rationale

JSON Web Tokens (JWTs) [@!RFC7519] can in principle be used to express
Verifiable Credentials in a way that is easy to understand and process as it
builds upon established web primitives.

Selective Disclosure JWT (SD-JWT) [@!I-D.ietf-oauth-selective-disclosure-jwt] is
a specification that introduces conventions to support selective disclosure for
JWTs: For an SD-JWT document, a Holder can decide which claims to release (within
bounds defined by the Issuer).

SD-JWT is a superset of JWT as it can also be used when there are no selectively
disclosable claims and also supports JWS JSON serialization, which is useful for
long term archiving and multi signatures. However, SD-JWT itself does not define
the claims that must be used within the payload or their semantics.

This specification therefore uses SD-JWT and the well-established JWT content rules and
extensibility model as basis for representing Verifiable Credentials with JSON payload.
Those Verifiable Credentials are called SD-JWT VCs.

SD-JWTs VC can contain claims that are registered in "JSON Web Token Claims"
registry as defined in [@!RFC7519], as well as public and
private claims.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [@!RFC2119].

## Terms and Definitions

This specification uses the terms "Holder", "Issuer", "Verifier", defined by
[@!I-D.ietf-oauth-selective-disclosure-jwt].

Verifiable Credential (VC):
:  An Issuer-signed assertion with claims about a Subject.

SD-JWT-based Verifiable Credential (SD-JWT VC):
: A Verifiable Credential encoded using the Issuance format defined in
[@!I-D.ietf-oauth-selective-disclosure-jwt]. It may or may not contain
selectively disclosable claims.

Unsecured payload of an SD-JWT VC:
: A JSON object containing all selectively disclosable and non-selectively disclosable claims
of the SD-JWT VC. The unsecured payload acts as the input JSON object to issue
an SD-JWT VC complying to this specification.

Status Provider:
: An entity that provides status information (e.g. revocation) about a Verifiable Credential.

# Scope

* This specification defines
  - Data model and media types for Verifiable Credentials based on SD-JWTs.
  - Validation and processing rules for Verifiers and Holders.

# Use Cases

TBD: explain use cases of the three-party-model.

TBD: conventional crypt, hardware security, hsm, mobile secure area,
compliance with FIPS

# Verifiable Credentials based on SD-JWT

This section defines encoding, validation and processing rules for SD-JWT VCs.

## Media Type

SD-JWT VCs compliant with this specification MUST use the media type
`application/vc+sd-jwt` as defined in (#application-vc-sd-jwt).

## Data Format

SD-JWT VCs MUST be encoded using the SD-JWT Combined Format for Issuance as
defined in Section 5.3. of [@!I-D.ietf-oauth-selective-disclosure-jwt].

When there are selectively disclosable claims, SD-JWT VCs MUST contain all
Disclosures corresponding to their SD-JWT component
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
The Issuer MAY use it to provide the Subject
identifier known by the Issuer. There is no requirement for a binding to
exist between `sub` and `cnf` claims.

#### Public JWT claims

Additional public claims MAY be used in SD-JWT VCs depending on the
application.

#### SD-JWT VC without Selectively Disclosable Claims

An SD-JWT VC MAY have no selectively disclosable claims.
In that case, the SD-JWT VC MUST NOT contain the `_sd` claim in the JWT body. It also
MUST NOT have any Disclosures.

## Example

The following is a non-normative example of an unsecured payload of an
SD-JWT VC.

<{{examples/01/user_claims.json}}

The following is a non-normative example of how the unsecured payload of the
SD-JWT VC above can be used in a SD-JWT where the resulting SD-JWT VC contains
only claims about the Subject that are selectively disclosable:

<{{examples/01/sd_jwt_payload.json}}

Note that a `cnf` claim has been added to the SD-JWT payload to express the
confirmation method of the holder binding.

The following are the Disclosures belonging to the SD-JWT payload above:

{{examples/01/disclosures.md}}

The SD-JWT and the Disclosures would then be serialized by the Issuer into the following format for issuance to the Holder:

<{{examples/01/combined_issuance.txt}}

## Verification and Processing {#vc-sd-jwt-verification-and-processing}

The recipient of the SD-JWT VC MUST process and verify an SD-JWT VC as
follows:

 1. REQUIRED. Process and verify the SD-JWT as defined in
Section 6. of [@!I-D.ietf-oauth-selective-disclosure-jwt]. For the
verification, the `iss` claim in the SD-JWT MAY be used to retrieve the public
key from the JWT Issuer Metadata configuration (as defined in
(#jwt-issuer-metadata)) of the SD-JWT VC issuer. A Verifier MAY use alternative
methods to obtain the public key to verify the signature of the SD-JWT.
If there are no selectively disclosable claims, there is no need to process the
`_sd` claim nor any Disclosures.
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

When there are no selectively disclosable claims, a presentation of SD-JWT VC
does not contain any Disclosures.

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

<{{examples/01/combined_presentation.txt}}

In this presentation, the Holder provides only the Disclosure for the claim
`address`. Other claims are not disclosed to the Verifier.

The following example shows a presentation of a (different) SD-JWT without a
Holder Binding JWT:

<{{examples/02/combined_presentation.txt}}

## Verification and Processing {#vp-sd-jwt-verification-and-processing}

The Verifier MUST process and verify a presentation of SD-JWT VC as follows:

 1. REQUIRED. When processing and verifying the presentation of the SD-JWT VC,
the Verifier MUST follow the same verification and processing rules as defined
in (#vc-sd-jwt-verification-and-processing).
 1. OPTIONAL. If provided, the Verifier MUST verify the Holder Binding JWT
according to Section 6.2. of [@!I-D.ietf-oauth-selective-disclosure-jwt].
To verify the Holder Binding JWT, the `cnf` claim of the SD-JWT MUST be used.

# Security Considerations {#security-considerations}

TBD: Verifier provided `nonce`.

# Privacy Considerations {#privacy-considerations}

TBD: Holder provided nonce via `jti`.

# Relationships to Other Documents

TBD

{backmatter}

<reference anchor="VC-DATA" target="https://www.w3.org/TR/vc-data-model-2.0/">
        <front>
        <title>Verifiable Credentials Data Model v2.0</title>
        <author fullname="Manu Sporny">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="Dave Longley">
            <organization>Digital Bazaar</organization>
        </author>
        <author fullname="David Chadwick">
            <organization>Crossword Cybersecurity PLC</organization>
        </author>
        <date day="4" month="May" year="2023"/>
        </front>
</reference>

<reference anchor="VC-DIR" target="https://w3c.github.io/vc-specs-dir/">
        <front>
        <title>VC Specifications Directory</title>
        <author fullname="Manu Sporny">
            <organization>Digital Bazaar</organization>
        </author>
        <date day="8" month="May" year="2023"/>
        </front>
</reference>

# IANA Considerations

## JSON Web Token Claims Registration

- Claim Name: "type"
  - Claim Description: Credential Type
  - Change Controller: IESG
  - Specification Document(s): (#type-claim) of this document

## Media Types Registry

### application/vc+sd-jwt {#application-vc-sd-jwt}

The Internet media type for a SD-JWT VC is `application/vc+sd-jwt`.

Type name: : `application`

Subtype name: : `vc+sd-jwt`

Required parameters: : n/a

Optional parameters: : n/a

Encoding considerations: : 8-bit code points; SD-JWT VC values are encoded as a
series of base64url-encoded values (some of which may be the empty string)
separated by period ('.') and tilde ('~') characters.

Security considerations: : See Security Considerations in (#security-considerations).

Interoperability considerations: : n/a

- Published specification: : RFC TODO
- Applications that use this media type: : Applications that issue, present,
  verify verifiable credentials and presentations.
- Additional information:
  - Magic number(s): n/a
  - File extension(s): n/a
  - Macintosh file type code(s): n/a
  - Person & email address to contact for further information: TBD
  - Intended usage: COMMON
  - Restrictions on usage: none
  - Author: Oliver Terbu <oliver.terbu@spruceid.com>
  - Change controller: IETF

# Acknowledgements {#Acknowledgements}

We would like to thank
Alen Horvat,
Andres Uribe,
Brian Campbell,
Christian Bormann,
Giuseppe De Marco,
Michael Jones,
Mike Prorock,
Orie Steele,
Paul Bastian,
Torsten Lodderstedt,
Tobias Looker, and
Kristina Yasuda
for their contributions (some of which substantial) to this draft and to the initial set of implementations.

# Document History

-03

* added non-selectively disclosable JWT VC

-02

* Adjusted terminology based on feedback

-01

* Removed W3C VCDM transformation algorithm
* Various editorial changes based on feedback

-00

* Initial Version
