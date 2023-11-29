%%%
title = "SD-JWT-based Verifiable Credentials (SD-JWT VC)"
abbrev = "SD-JWT VC"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2", "sd-jwt"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-sd-jwt-vc-latest"
stream = "IETF"
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

[[author]]
initials="B."
surname="Campbell"
fullname="Brian Campbell"
organization="Ping Identity"
    [author.address]
    email = "bcampbell@pingidentity.com"

%%%

.# Abstract

This specification describes data formats as well as validation and processing
rules to express Verifiable Credentials with JSON payloads with and without selective disclosure based on the SD-JWT [@!I-D.ietf-oauth-selective-disclosure-jwt] format.

{mainmatter}

# Introduction

## Issuer-Holder-Verifier Model

In the so-called Issuer-Holder-Verifier Model, Issuers issue so-called Verifiable Credentials to a
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
Figure: Issuer-Holder-Verifier Model with optional Status Provider

Verifiers can check the authenticity of the data in the Verifiable Credentials
and optionally enforce Key Binding, i.e., ask the Holder to prove that they
are the intended holder of the Verifiable Credential, for example, by proving possession of a
cryptographic key referenced in the credential. This process is further
described in [@!I-D.ietf-oauth-selective-disclosure-jwt].

To support revocation of Verifiable Credentials, revocation information can
optionally be retrieved from a Status Provider. The role of a Status Provider
can be fulfilled by either a fourth party or by the Issuer.

## SD-JWT as a Credential Format

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

This specification uses SD-JWT and the well-established JWT content rules and
extensibility model as basis for representing Verifiable Credentials with JSON
payloads. These Verifiable Credentials are called SD-JWT VCs. The use of
selective disclosure in SD-JWT VCs is OPTIONAL.

SD-JWTs VC can contain claims that are registered in "JSON Web Token Claims"
registry as defined in [@!RFC7519], as well as public and
private claims.

Note: This specification does not utilize the W3C's Verifiable Credentials Data Model v1.0, v1.1, or v2.0.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [@!RFC2119].

## Terms and Definitions

This specification uses the terms "Holder", "Issuer", "Verifier", "Key Binding JWT" defined by
[@!I-D.ietf-oauth-selective-disclosure-jwt].

Verifiable Credential (VC):
:  An Issuer-signed assertion with claims about a Subject.

SD-JWT-based Verifiable Credential (SD-JWT VC):
: A Verifiable Credential encoded using the format defined in
[@!I-D.ietf-oauth-selective-disclosure-jwt]. It may or may not contain
selectively disclosable claims.

Unsecured Payload of an SD-JWT VC:
: A JSON object containing all selectively disclosable and non-selectively disclosable claims
of the SD-JWT VC. The Unsecured Payload acts as the input JSON object to issue
an SD-JWT VC complying to this specification.

Status Provider:
: An entity that provides status information (e.g. revocation) about a Verifiable Credential.

# Scope

* This specification defines
  - Data model and media types for Verifiable Credentials based on SD-JWTs.
  - Validation and processing rules for Verifiers and Holders.

# Verifiable Credentials based on SD-JWT

This section defines encoding, validation and processing rules for SD-JWT VCs.

## Media Type

SD-JWT VCs compliant with this specification MUST use the media type
`application/vc+sd-jwt` as defined in (#application-vc-sd-jwt).

## Data Format

SD-JWT VCs MUST be encoded using the SD-JWT format defined in Section 5 of
[@!I-D.ietf-oauth-selective-disclosure-jwt]. A presentation of an SD-JWT VC MAY
contain a Key Binding JWT.

Note that in some cases, an SD-JWT VC MAY have no selectively disclosable
claims, and therefore the encoded SD-JWT will not contain any Disclosures.

### JOSE Header

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

### JWT Claims Set

This section defines the claims that can be included in the payload of
SD-JWT VCs.

#### New JWT Claims

##### Verifiable Credential Type - `vct` Claim {#type-claim}

This specification defines the JWT claim `vct` (for verifiable credential type). The `vct` value MUST be a
case-sensitive `StringOrURI` (see [@!RFC7519]) value serving as an identifier
for the type of the SD-JWT VC. The `vct` value MUST be a Collision-Resistant
Name as defined in Section 2 of [@!RFC7515].

A type is associated with rules defining which claims may or must appear in the
Unsecured Payload of the SD-JWT VC and whether they may, must, or must not be
selectively disclosable. This specification does not define any `vct` values; instead
it is expected that ecosystems using SD-JWT VCs define such values including
the semantics of the respective claims and associated rules (e.g., policies for issuing and
validating credentials beyond what is defined in this specification).

The following is a non-normative example of how `vct` is used to express
a type:

```
{
  "vct": "https://credentials.example.com/identity_credential"
}
```
For example, a value of `https://credentials.example.com/identity_credential` can be associated with rules that define that at least the registered JWT claims `given_name`, `family_name`, `birthdate`, and `address` must appear in the Unsecured Payload. Additionally, the registered JWT claims `email` and `phone_number`, and the private claims `is_over_18`, `is_over_21`, and `is_over_65` may be used. The type might also indicate that any of the aforementioned claims can be selectively disclosable.

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
    * REQUIRED when Cryptographic Key Binding is to be supported. Contains the confirmation method as defined in [@!RFC7800]. It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of [@!RFC7800]. For Cryptographic Key Binding, the Key Binding JWT in the Combined Format for Presentation MUST be signed by the key identified in this claim.
* `vct`
    * REQUIRED. The type of the Verifiable Credential, e.g.,
`https://credentials.example.com/identity_credential`, as defined in (#type-claim).
* `status`
    * OPTIONAL. The information on how to read the status of the Verifiable
Credential. See [@!I-D.looker-oauth-jwt-cwt-status-list]
 for more information.

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
confirmation method of the Key Binding.

The following are the Disclosures belonging to the SD-JWT payload above:

{{examples/01/disclosures.md}}

The SD-JWT and the Disclosures would then be serialized by the Issuer into the following format for issuance to the Holder:

<{{examples/01/sd_jwt_issuance.txt}}

## Verification and Processing {#vc-sd-jwt-verification-and-processing}

The recipient (Holder or Verifier) of an SD-JWT VC MUST process and verify an
SD-JWT VC as described in Section 8 of
[@!I-D.ietf-oauth-selective-disclosure-jwt].

If Key Binding is required (refer to the security considerations in Section 11.6 of [@!I-D.ietf-oauth-selective-disclosure-jwt]), the Verifier MUST verify the Key Binding JWT
according to Section 8 of [@!I-D.ietf-oauth-selective-disclosure-jwt]. To verify
the Key Binding JWT, the `cnf` claim of the SD-JWT MUST be used.

Furthermore, the recipient of the SD-JWT VC MUST validate that the public verification key
for the Issuer-signed JWT as defined in (#issuer-signed-jwt-verification-key-validation).

If there are no selectively disclosable claims, there is no need to process the
`_sd` claim nor any Disclosures.

If `status` is present in the verified payload of the SD-JWT, the status SHOULD
be checked. It depends on the Verifier policy to reject or accept a presentation
of a SD-JWT VC based on the status of the Verifiable Credential.

Any claims used that are not understood MUST be ignored.

Additional validation rules MAY apply, but their use is out of the scope of this
specification.

## Issuer-signed JWT Verification Key Validation {#issuer-signed-jwt-verification-key-validation}

A recipient of an SD-JWT VC MUST apply the following rules to validate that the public
verification key for the Issuer-signed JWT corresponds to the `iss` value:

- JWT VC Issuer Metadata: If a recipient supports JWT VC Issuer Metadata and if the `iss` value contains an HTTPS URI, the recipient MUST
obtain the public key using JWT VC Issuer Metadata as defined in (#jwt-vc-issuer-metadata).
- X.509 Certificates: If the recipient supports X.509 Certificates, the recipient MUST obtain the public key from the leaf X.509 certificate defined by the `x5c` JWT header parameters of the Issuer-signed JWT and validate the X.509
certificate chain in the following cases:
    - If the `iss` value contains a DNS name encoded as a URI using the DNS URI scheme [@RFC4501], the DNS name MUST match a `dNSName` Subject Alternative Name (SAN) [@RFC5280] entry of the leaf certificate.
    - In all other cases, the `iss` value MUST match a `uniformResourceIdentifier` SAN entry of the leaf certificate.
- DID Document Resolution: If a recipient supports DID Document Resolution and if the `iss` value contains a DID [@W3C.DID], the recipient MUST retrieve the public key from the DID Document resolved from the DID in the `iss` value. In this case, if the `kid` JWT header parameter is present, the `kid` MUST be a relative or absolute DID URL of the DID in the `iss` value, identifying the public key.

Separate specifications or ecosystem regulations MAY define rules complementing the rules defined above, but such rules are out of scope of this specification. See (#ecosystem-verification-rules) for security considerations.

If a recipient cannot validate that the public verification key corresponds to the `iss` value of the Issuer-signed JWT,
the SD-JWT VC MUST be rejected.

# Presenting Verifiable Credentials

This section defines encoding, validation and processing rules for presentations
of SD-JWT VCs.

## Key Binding JWT

If the presentation of the SD-JWT VC includes a Key Binding JWT, the Key Binding
JWT MUST adhere to the rules defined in Section 5.3 of
[@!I-D.ietf-oauth-selective-disclosure-jwt].

The Key Binding JWT MAY include addtional claims which, when not understood, MUST
be ignored by the Verifier.

## Examples

The following is a non-normative example of a presentation of the SD-JWT shown
above including a Key Binding JWT:

<{{examples/01/sd_jwt_presentation.txt}}

In this presentation, the Holder provides only the Disclosure for the claim
`address`. Other claims are not disclosed to the Verifier.

The following example shows a presentation of a (different) SD-JWT without a
Key Binding JWT:

<{{examples/02/sd_jwt_presentation.txt}}

# JWT VC Issuer Metadata {#jwt-vc-issuer-metadata}

This specification defines the JWT VC Issuer Metadata to retrieve the JWT VC
Issuer Metadata configuration of the Issuer of the SD-JWT VC. The Issuer
is identified by the `iss` claim in the JWT. Use of the JWT VC Issuer Metadata
is OPTIONAL.

Issuers publishing JWT VC Issuer Metadata MUST make a JWT VC Issuer Metadata
configuration available at the path formed by concatenating the string
`/.well-known/jwt-vc-issuer` to the `iss` claim value in the JWT. The `iss` MUST
be a case-sensitive URL using the HTTPS scheme that contains scheme, host and,
optionally, port number and path components, but no query or fragment
components.

## JWT VC Issuer Metadata Request

A JWT VC Issuer Metadata configuration MUST be queried using an HTTP `GET` request
at the path defined in (#jwt-vc-issuer-metadata).

The following is a non-normative example of a HTTP request for the JWT VC Issuer
Metadata configuration when `iss` is set to `https://example.com`:

```
GET /.well-known/jwt-vc-issuer HTTP/1.1
Host: example.com
```

If the `iss` value contains a path component, any terminating `/` MUST be
removed before inserting `/.well-known/` and the well-known URI suffix
between the host component and the path component.

The following is a non-normative example of a HTTP request for the JWT VC Issuer
Metadata configuration when `iss` is set to `https://example.com/user/1234`:

```
GET /.well-known/jwt-vc-issuer/user/1234 HTTP/1.1
Host: example.com
```

## JWT VC Issuer Metadata Response

A successful response MUST use the `200 OK HTTP` and return the JWT VC Issuer
Metadata configuration using the `application/json` content type.

An error response uses the applicable HTTP status code value.

This specification defines the following JWT VC Issuer Metadata configuration
parameters:

* `issuer`
      REQUIRED. The Issuer identifier, which MUST be identical to the `iss`
value in the JWT.
* `jwks_uri`
    * OPTIONAL. URL string referencing the Issuer's JSON Web Key (JWK) Set
[@RFC7517] document which contains the Issuer's public keys. The value of
this field MUST point to a valid JWK Set document.
* `jwks`
    * OPTIONAL. Issuer's JSON Web Key Set [@RFC7517] document value, which
contains the Issuer's public keys. The value of this field MUST be a JSON
object containing a valid JWK Set.

JWT VC Issuer Metadata MUST include either `jwks_uri` or `jwks` in their JWT VC
Issuer Metadata, but not both.

It is RECOMMENDED that the JWT contains a `kid` JWT header parameter that can
be used to lookup the public key in the JWK Set included by value or referenced
in the JWT VC Issuer Metadata.

The following is a non-normative example of a JWT VC Issuer Metadata configuration
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

The following is a non-normative example of a JWT VC Issuer Metadata
configuration including `jwks_uri`:

```
{
   "issuer":"https://example.com",
   "jwks_uri":"https://jwt-vc-issuer.example.org/my_public_keys.jwks"
}
```

Additional JWT VC Issuer Metadata configuration parameters MAY also be used.

## JWT VC Issuer Metadata Validation

The `issuer` value returned MUST be identical to the `iss` value of the JWT. If
these values are not identical, the data contained in the response MUST NOT be
used.

# Security Considerations {#security-considerations}

The Security Considerations in the SD-JWT specification
[@!I-D.ietf-oauth-selective-disclosure-jwt] apply to this specification.
Additionally, the following security considerations need to be taken into
account when using SD-JWT VCs:

## Server-Side Request Forgery

The JWT VC Issuer Metadata configuration is retrieved from the JWT VC Issuer by the
Holder or Verifier. Similar to other metadata endpoints, the URL for the
retrieval MUST be considered an untrusted value and could be a vector for
Server-Side Request Forgery (SSRF) attacks.

Before making a request to the JWT VC Issuer Metadata endpoint, the Holder or
Verifier MUST validate the URL to ensure that it is a valid HTTPS URL and that
it does not point to internal resources. This requires, in particular, ensuring
that the host part of the URL does not address an internal service (by IP
address or an internal host name) and that, if an external DNS name is used, the
resolved DNS name does not point to an internal IPv4 or IPv6 address.

When retrieving the metadata, the Holder or Verifier MUST ensure that the
request is made in a time-bound and size-bound manner to prevent denial of
service attacks. The Holder or Verifier MUST also ensure that the response is a
valid JWT VC Issuer Metadata configuration document before processing it.

Additional considerations can be found in [@OWASP_SSRF].

## Ecosystem-specific Public Key Verification Methods {#ecosystem-verification-rules}

When defining ecosystem-specific rules for the verification of the public key,
as outlined in (#issuer-signed-jwt-verification-key-validation), it is critical
that those rules maintain the integrity of the relationship between the `iss` value
within the Issuer-signed JWT and the public keys of the Issuer.

It MUST be ensured that for any given `iss` value, an attacker cannot influence
the type of verification process used. Otherwise, an attacker could attempt to make
the Verifier use a verification process not intended by the Issuer, allowing the
attacker to potentially manipulate the verification result to their advantage.

# Privacy Considerations {#privacy-considerations}

The Privacy Considerations in the SD-JWT specification
[@!I-D.ietf-oauth-selective-disclosure-jwt] apply to this specification.
Additionally, the following privacy considerations need to be taken into
account when using SD-JWT VCs.

## Unlinkability

The Privacy Considerations in Section 12.5 of [@!I-D.ietf-oauth-selective-disclosure-jwt]
apply especially to the `cnf` claim.

## Verifiable Credential Type Identifier

Issuers and Holders have to be aware that while this specification supports selective
disclosure of claims of a given SD-JWT VC, the `vct` claim is not selectively disclosable.
In certain situations this could lead to unwanted leakage of additional context information.

In general, Issuers are advised to choose `vct` values following data minimization principles.
For example, government Issuers issuing an SD-JWT VC to their citizens to enable them to prove their age,
might consider using a `vct` value that does not allow third-parties to infer additional personal information
about the Holder, e.g., country of residency or citizenship.

Additionally, Holders have to be informed that, besides the actual requested claims, the
`vct` information is shared with the Verifier.

## Issuer Phone-Home

A malicious Issuer can choose the Issuer identifier of the SD-JWT VC to enable tracking
the usage behavior of the Holder if the Issuer identifier is Holder-specific and if the
resolution of the key material to verify the Issuer-signed JWT requires the Verifier
to phone home to the Issuer.

For example, a malicious Issuer could generate a unique value for the Issuer identifier
per Holder, e.g., `https://example.com/issuer/holder-1234` and host the JWT VC Issuer Metadata.
The Verifier would create a HTTPS GET request to the Holder-specific well-known URI
when the SD-JWT VC is verified. This would allow the malicious Issuer to keep track where
and how often the SD-JWT VC was used.

Verifiers are advised to establish trust in an SD-JWT VC by pinning specific Issuer identifiers
and should monitor suspicious behaviour such as frequently rotating Issuer identifiers.
If such behaviour was detected, Verifiers are advised to reject SD-JWT VCs issued by such
Issuers.

Holders are advised to reject SD-JWT VCs if they contain easily correlatable information
in the Issuer identifier.

# Relationships to Other Documents

TBD

<reference anchor="OWASP_SSRF" target="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html/">
  <front>
    <author fullname="OWASP"></author>
    <title>Server Side Request Forgery Prevention Cheat Sheet</title>
  </front>
</reference>

<reference anchor="W3C.DID" target="https://www.w3.org/TR/did-core/">
    <front>
        <author initials="M." surname="Sporny" fullname="Manu Sporny">
            <organization>
                <organizationName>Digital Bazaar</organizationName>
            </organization>
        </author>
        <author initials="D." surname="Longley" fullname="Dave Longley">
            <organization>
                <organizationName>Digital Bazaar</organizationName>
            </organization>
        </author>
        <author initials="M." surname="Sabadello" fullname="Markus Sabadello">
            <organization>
                <organizationName>Danube Tech</organizationName>
            </organization>
        </author>
        <author initials="D." surname="Reed" fullname="Drummond Reed">
            <organization>
                <organizationName>Evernym/Avast</organizationName>
            </organization>
        </author>
        <author initials="O." surname="Steele" fullname="Orie Steele">
            <organization>
                <organizationName>Transmute</organizationName>
            </organization>
        </author>
        <author initials="C." surname="Allen" fullname="Christopher Allen">
            <organization>
                <organizationName>Blockchain Commons</organizationName>
            </organization>
        </author>
        <title>Decentralized Identifiers (DIDs) v1.0</title>
        <date day="19" month="July" year="2022"/>
    </front>
</reference>
{backmatter}

# IANA Considerations

## JSON Web Token Claims Registration

- Claim Name: "vct"
  - Claim Description: Verifiable credential type identifier
  - Change Controller: IETF
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

-02

* Made specific rules for public verification key validation conditional
* Finetuned rules for obtaining public verification key
* Editorial changes
* Renamed JWT Issuer Metadata to JWT VC Issuer Metadata

-01

* Introduce rules for type identifiers (Collision-Resistant Name)
* Rename `type` to `vct`
* Removed duplicated and inconsistent requirements on KB-JWT
* Editorial changes
* Added issuer public verification key discovery section.

-00

* Upload as draft-ietf-oauth-sd-jwt-vc-00
* Aligned terminology and descriptions with latest version of SD-JWT

[[ pre Working Group Adoption: ]]

-00

* Initial Version
* Removed W3C VCDM transformation algorithm
* Various editorial changes based on feedback
* Adjusted terminology based on feedback
* Added non-selectively disclosable JWT VC
* Added a note that this is not W3C VCDM

