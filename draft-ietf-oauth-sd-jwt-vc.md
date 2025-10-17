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
organization="MATTR"
    [author.address]
    email = "oliver.terbu@mattr.global"

[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="Authlete Inc."
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
Credentials are cryptographically secured statements about a Subject, typically the Holder.

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
         |             |-+
         |  Verifiers  | |-+
         |             | | |
         +-------------+ | |
           +-------------+ |
             +-------------+
~~~
Figure: Issuer-Holder-Verifier Model

Verifiers can check the authenticity of the data in the Verifiable Credentials
and optionally enforce Key Binding, i.e., ask the Holder to prove that they
are the intended Holder of the Verifiable Credential, for example, by proving possession of a
cryptographic key referenced in the credential. This process is further
described in [@!I-D.ietf-oauth-selective-disclosure-jwt].

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

This specification uses the terms "Holder", "Issuer", "Verifier", "Disclosure", "Selectively Disclosable JWT (SD-JWT)", "Key Binding",
"Key Binding JWT (KB-JWT)", "Selectively Disclosable JWT with Key Binding (SD-JWT+KB)" defined by
[@!I-D.ietf-oauth-selective-disclosure-jwt].

Consumer:
: Applications using the Type Metadata specified in (#type-metadata) are called Consumer. This typically includes Issuers, Verifiers, and Wallets.

Verifiable Credential (VC):
:  An assertion with claims about a Subject that is cryptographically secured by an Issuer (usually by a digital signature).

SD-JWT-based Verifiable Credential (SD-JWT VC):
: A Verifiable Credential encoded using the format defined in
[@!I-D.ietf-oauth-selective-disclosure-jwt]. It may or may not contain
selectively disclosable claims.

Unsecured Payload of an SD-JWT VC:
: A JSON object containing all selectively disclosable and non-selectively disclosable claims
of the SD-JWT VC. The Unsecured Payload acts as the input JSON object to issue
an SD-JWT VC complying to this specification.

# Scope

* This specification defines
  - Data model and media types for Verifiable Credentials based on SD-JWTs.
  - Validation and processing rules for Verifiers and Holders.

# Verifiable Credentials based on SD-JWT

This section defines encoding, validation and processing rules for SD-JWT VCs.

## Media Type

SD-JWT VCs compliant with this specification MUST use the media type
`application/dc+sd-jwt` as defined in (#media-type).

The base subtype name `dc` is meant to stand for "digital credential", which is
a term that is emerging as a conceptual synonym for "verifiable credential".

## Data Format

SD-JWT VCs MUST be encoded using the SD-JWT format defined in Section 4 of
[@!I-D.ietf-oauth-selective-disclosure-jwt]. A presentation of an SD-JWT VC MAY
have an associated KB-JWT (i.e., the presentation is an SD-JWT+KB).

Note that in some cases, an SD-JWT VC MAY have no selectively disclosable
claims, and therefore the encoded SD-JWT will not contain any Disclosures.

### JOSE Header

This section defines JWT header parameters for the SD-JWT component of the
SD-JWT VC.

The `typ` header parameter of the SD-JWT MUST be present. The `typ` value MUST
use `dc+sd-jwt`. This indicates that the payload of the SD-JWT contains plain
JSON and follows the rules as defined in this specification. It further
indicates that the SD-JWT is a SD-JWT component of a SD-JWT VC.

The following is a non-normative example of a decoded SD-JWT header:

```
{
  "alg": "ES256",
  "typ": "dc+sd-jwt"
}
```

Note that this draft used `vc+sd-jwt` as the value of the `typ` header from its inception in July 2023 until November 2024 when it was changed to `dc+sd-jwt` to avoid conflict with the `vc` media type name registered by the W3C's Verifiable Credentials Data Model draft. In order to facilitate a minimally disruptive transition, it is RECOMMENDED that Verifiers and Holders accept both `vc+sd-jwt` and `dc+sd-jwt` as the value of the `typ` header for a reasonable transitional period.

### JWT Claims Set

This section defines the claims that can be included in the payload of
SD-JWT VCs.

#### Verifiable Credential Type - `vct` Claim {#type-claim}

This specification defines the new JWT claim `vct` (for verifiable credential type). The `vct` value MUST be a
case-sensitive string value serving as an identifier
for the type of the SD-JWT VC. The `vct` value MUST be a Collision-Resistant
Name as defined in Section 2 of [@!RFC7515].

A type is associated with rules defining which claims may or must appear in the
Unsecured Payload of the SD-JWT VC and whether they may, must, or must not be
selectively disclosable. This specification does not define any `vct` values; instead
it is expected that ecosystems using SD-JWT VCs define such values including
the semantics of the respective claims and associated rules (e.g., policies for issuing and
validating credentials beyond what is defined in this specification).

The `vct` value also effectively identifies the version of the credential type definition,
as it ties a particular instance of a credential to a specific structure, set of semantics and rules.
When evolving a credential type without updating the version, changes to the structure or meaning of the associated claims
need to be made in a way that preserves compatibility with existing implementations.

If a change alters the meaning of existing content, adds new required claims, removes
previously required elements, or otherwise introduces incompatibilities, it is
generally advisable to treat that as a new version of the credential type and to
convey it using a new `vct` value. This allows different versions of a credential
type to coexist and helps ensure that participants interpret credentials consistently.

The following is a non-normative example of how `vct` is used to express
a type:

```
{
  "vct": "https://credentials.example.com/identity_credential"
}
```
For example, a value of `https://credentials.example.com/identity_credential` can be associated with rules that define that at least the registered JWT claims `given_name`, `family_name`, `birthdate`, and `address` must appear in the Unsecured Payload. Additionally, the registered JWT claims `email` and `phone_number`, and the private claims `is_over_18`, `is_over_21`, and `is_over_65` may be used. The type might also indicate that any of the aforementioned claims can be selectively disclosable.

#### Registered JWT Claims {#claims}

SD-JWT VCs MAY use any claim registered in the "JSON Web Token Claims"
registry as defined in [@!RFC7519].

The following registered JWT claims are used within the SD-JWT component of the SD-JWT VC and MUST NOT be included in the Disclosures, i.e., cannot be selectively disclosed:

* `iss`: OPTIONAL. As defined in [@!RFC7519, section 4.1.1] this claim explicitly indicates the Issuer of the Verifiable Credential
    when it is not conveyed by other means (e.g., the subject of the end-entity certificate of an `x5c` header).
* `nbf`: OPTIONAL. The time before which the Verifiable Credential MUST NOT be
accepted before validating. See [@!RFC7519] for more information.
* `exp`: OPTIONAL. The expiry time of the Verifiable Credential after which the
Verifiable Credential is no longer valid. See [@!RFC7519] for more
information.
* `cnf`: OPTIONAL unless cryptographic Key Binding is to be supported, in which case it is REQUIRED. Contains the confirmation method identifying the proof of possession key as defined in [@!RFC7800]. It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of [@!RFC7800]. For proof of cryptographic Key Binding, the KB-JWT in the presentation of the SD-JWT MUST be secured by the key identified in this claim.
* `vct`: REQUIRED. The type of the Verifiable Credential, e.g.,
`https://credentials.example.com/identity_credential`, as defined in (#type-claim).
* `vct#integrity`: OPTIONAL. The hash of the Type Metadata document to provide integrity as defined in (#document-integrity).
* `status`: OPTIONAL. The information on how to read the status of the Verifiable
Credential. See [@!I-D.ietf-oauth-status-list]
 for more information. When the `status` claim is present and using the `status_list` mechanism, the associated Status List Token MUST be in JWT format.

The following registered JWT claims are used within the SD-JWT component of the SD-JWT VC and MAY be included in Disclosures, i.e., can be selectively disclosed:

* `sub`: OPTIONAL. The identifier of the Subject of the Verifiable Credential.
The Issuer MAY use it to provide the Subject
identifier known by the Issuer. There is no requirement for a binding to
exist between `sub` and `cnf` claims.
* `iat`: OPTIONAL. The time of issuance of the Verifiable Credential. See
      [@!RFC7519] for more information.

#### Public and Private JWT claims

Additionally, any public and private claims as defined in Sections 4.2 and 4.3 of
[@!RFC7519] MAY be used.

Binary data in claims SHOULD be encoded as data URIs as defined in [@!RFC2397]. Exceptions can be made when data formats are used that already define a text encoding suitable for use in JSON or where an established text encoding is commonly used. For example, images would make use of data URIs, whereas hash digests in base64 encoding do not need to be encoded as such.

The following is a non-normative example of user data in the unsecured payload
of an SD-JWT VC that includes a binary image claim:

```json
{
  "vct": "https://credentials.example.com/identity_credential",
  "given_name": "Jane",
  "family_name": "Doe",
  "portrait": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA
   AAAFCAYAAACNbyblAAAAHElEQVQI12P4
   //8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg=="
}
```

#### SD-JWT VC without Selectively Disclosable Claims

An SD-JWT VC MAY have no selectively disclosable claims.
In that case, the SD-JWT VC MUST NOT contain the `_sd` claim in the JWT body. It also
MUST NOT have any Disclosures.

## Example {#vc-sd-jwt-example}

The following is a non-normative example of the user data of an unsecured payload of an
SD-JWT VC.

<{{examples/01/user_claims.json}}

The following is a non-normative example of how the unsecured payload of the
SD-JWT VC above can be used in an SD-JWT where the resulting SD-JWT VC contains
only claims about the Subject that are selectively disclosable:

<{{examples/01/sd_jwt_payload.json}}

Note that a `cnf` claim has been added to the SD-JWT payload to express the
confirmation method of the Key Binding.

The following are the Disclosures belonging to the SD-JWT payload above:

{{examples/01/disclosures.md}}

The SD-JWT and the Disclosures would then be serialized by the Issuer into the following format for issuance to the Holder:

<{{examples/01/sd_jwt_issuance.txt}}

Examples of what presentations of SD-JWT VCs might look like are provided in (#presentation-examples).

## Verification and Processing {#vc-sd-jwt-verification-and-processing}

The recipient (Holder or Verifier) of an SD-JWT VC MUST process and verify an
SD-JWT VC as described in [@!I-D.ietf-oauth-selective-disclosure-jwt, section 7].
The check in point 2.3 of Section 7.1 of [@!I-D.ietf-oauth-selective-disclosure-jwt],
which validates the Issuer and ensures that the signing key belongs to the Issuer,
MUST be satisfied by determining and validating the public verification key used to verify the Issuer-signed JWT,
employing an Issuer Signature Mechanism (defined in (#ism)) that is permitted for the Issuer according to policy.

If Key Binding is required (refer to the security considerations in Section 9.5 of [@!I-D.ietf-oauth-selective-disclosure-jwt]), the Verifier MUST verify the KB-JWT
according to Section 7.3 of [@!I-D.ietf-oauth-selective-disclosure-jwt]. To verify
the KB-JWT, the `cnf` claim of the SD-JWT MUST be used.

If there are no selectively disclosable claims, there is no need to process the
`_sd` claim nor any Disclosures.

If `status` is present in the verified payload of the SD-JWT, the status SHOULD
be checked. It depends on the Verifier policy to reject or accept a presentation
of a SD-JWT VC based on the status of the Verifiable Credential.

Additional validation rules MAY apply, but their use is out of the scope of this
specification.

## Issuer Signature Mechanisms {#ism}

An Issuer Signature Mechanism defines how a Verifier determines the appropriate key and associated procedure for
verifying the signature of an Issuer-signed JWT.
This allows for flexibility in supporting different trust anchoring systems and key resolution methods
without changing the core processing model.

A recipient MUST determine and validate the public verification key for the Issuer-signed JWT using
a supported Issuer Signature Mechanism that is permitted for the given Issuer according to policy.
This specification defines the following two Issuer Signature Mechanisms:

- JWT VC Issuer Metadata: A mechanism to retrieve the Issuer's public key using web-based resolution. When the value of the `iss` claim of the Issuer-signed JWT is an HTTPS URI, the recipient obtains the public key using the keys from JWT VC Issuer Metadata as defined in (#jwt-vc-issuer-metadata).

- X.509 Certificates: A mechanism to retrieve the Issuer's public key using the X.509 certificate chain in the SD-JWT header. When the protected header of the Issuer-signed JWT contains the `x5c` parameter, the recipient uses the public key from the end-entity certificate of the certificates from that `x5c` parameter and validates the X.509 certificate chain accordingly. In this case, the Issuer of the Verifiable Credential is the subject of the end-entity certificate.

To enable different trust anchoring systems or key resolution methods, separate specifications or ecosystem regulations
may define additional Issuer Signature Mechanisms; however, the specifics of such mechanisms are out of scope for this specification.
See (#ecosystem-verification-rules) for related security considerations.

If a recipient cannot validate that the public verification key corresponds the Issuer of the Issuer-signed JWT using a permitted Issuer Signature Mechanism, the SD-JWT VC MUST be rejected.

# Presenting Verifiable Credentials

This section defines encoding, validation and processing rules for presentations
of SD-JWT VCs.

## Data Format

A presentation of an SD-JWT VC MUST be encoded as an SD-JWT, or as an SD-JWT+KB,
as defined in Section 4 of [@!I-D.ietf-oauth-selective-disclosure-jwt].

## Key Binding JWT

If the presentation of the SD-JWT VC is encoded as an SD-JWT+KB, the KB-JWT
MUST adhere to the rules defined in Section 4.3 of
[@!I-D.ietf-oauth-selective-disclosure-jwt].

The KB-JWT MAY include additional claims which, when not understood, MUST
be ignored by the Verifier.

## Examples {#presentation-examples}

The following is a non-normative example of a presentation of the SD-JWT shown in (#vc-sd-jwt-example) including a KB-JWT.
In this presentation, the Holder provides only the Disclosures for the `address` and `is_over_65` claims.
Other claims are not disclosed to the Verifier.

<{{examples/01/sd_jwt_presentation.txt}}

After validation, the Verifier will have the following processed SD-JWT payload available for further handling:

<{{examples/01/verified_contents.json}}

The following example shows a presentation of a (similar but different) SD-JWT without a
KB-JWT:

<{{examples/02/sd_jwt_presentation.txt}}

The Verifier will have the following processed SD-JWT payload after validation:

<{{examples/02/verified_contents.json}}

# JWT VC Issuer Metadata {#jwt-vc-issuer-metadata}

This specification defines the JWT VC Issuer Metadata to retrieve the JWT VC
Issuer Metadata configuration of the Issuer of the SD-JWT VC. The Issuer
is identified by the `iss` claim in the JWT. Use of the JWT VC Issuer Metadata
is OPTIONAL.

Issuers publishing JWT VC Issuer Metadata MUST make a JWT VC Issuer Metadata
configuration available at the location formed by inserting the well-known string
`/.well-known/jwt-vc-issuer` between the host component and the path
component (if any) of the `iss` claim value in the JWT. The `iss` MUST
be a case-sensitive URL using the HTTPS scheme that contains scheme, host and,
optionally, port number and path components, but no query or fragment
components.

## JWT VC Issuer Metadata Request

A JWT VC Issuer Metadata configuration MUST be queried using an HTTP `GET` request
at the path defined in (#jwt-vc-issuer-metadata).

The following is a non-normative example of an HTTP request for the JWT VC Issuer
Metadata configuration when `iss` is set to `https://example.com`:

```
GET /.well-known/jwt-vc-issuer HTTP/1.1
Host: example.com
```

If the `iss` value contains a path component, any terminating `/` MUST be
removed before inserting `/.well-known/` and the well-known URI suffix
between the host component and the path component.

The following is a non-normative example of an HTTP request for the JWT VC Issuer
Metadata configuration when `iss` is set to `https://example.com/tenant/1234`:

```
GET /.well-known/jwt-vc-issuer/tenant/1234 HTTP/1.1
Host: example.com
```

## JWT VC Issuer Metadata Response

A successful response MUST use the `200 OK HTTP` and return the JWT VC Issuer
Metadata configuration using the `application/json` content type.

An error response uses the applicable HTTP status code value.

This specification defines the following JWT VC Issuer Metadata configuration
parameters:

* `issuer`: REQUIRED. The Issuer identifier, which MUST be identical to the `iss`
value in the JWT.
* `jwks_uri`: OPTIONAL. URL string referencing the Issuer's JSON Web Key (JWK) Set
[@!RFC7517] document which contains the Issuer's public keys. The value of
this field MUST point to a valid JWK Set document.
  * `jwks`: OPTIONAL. Issuer's JSON Web Key Set [@!RFC7517] document value, which
  contains the Issuer's public keys. The value of this field MUST be a JSON
  object containing a valid JWK Set.

JWT VC Issuer Metadata MUST include either `jwks_uri` or `jwks` in their JWT VC
Issuer Metadata, but not both.

It is RECOMMENDED that the JWT contains a `kid` JWT header parameter that can
be used to look up the public key in the JWK Set included by value or referenced
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
            "kty": "EC", "crv": "P-256",
            "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
            "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
         },
         {
            "kid":"doc-signer-06-05-2025",
            "kty": "EC", "crv": "P-256",
            "x":"DfjUx4WHBds61vGbqUQhsy3FGX13fAS13QWh2EHIkX8",
            "y":"NfqJt9Kp0EA93xq9ysO80DRZ_hCGlISz-pYLgv4RFvg"
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
   "jwks_uri":"https://jwt-vc-issuer.example.com/my_public_keys.jwks"
}
```

Additional JWT VC Issuer Metadata configuration parameters MAY also be used.

## JWT VC Issuer Metadata Validation

The `issuer` value returned MUST be identical to the `iss` value of the
JWT. If these values are not identical, the data contained in the response
MUST NOT be used.

# SD-JWT VC Type Metadata {#type-metadata}

An SD-JWT VC type, i.e., the `vct` value, is associated with Type Metadata defining, for example, information about the type and how credentials are displayed.

This section defines Type Metadata that can be associated with a type of an SD-JWT VC, as well as a method for retrieving the Type Metadata and processing rules. This Type Metadata is intended to be used, among other things, for the following purposes:

 * Developers of Issuers and Verifiers can use the Type Metadata to understand the
   semantics of the type and the associated rules. While in some cases,
   Issuers are the parties that define types, this is
   not always the case. For example, a type can be defined by a
   standardization body or a community.
 * Verifiers can use the Type Metadata to determine whether a credential is valid
   according to the rules of the type. For example, a Verifier can check
   whether a credential contains all required claims and whether the claims
   are selectively disclosable.
 * Wallets can use the metadata to display the credential in a way that is
   consistent with the intent of the provider of the Type Metadata.

Type Metadata can be retrieved as described in (#retrieving-type-metadata).

## Type Metadata Example {#type-metadata-example}

All examples in this section are non-normative. This section only shows
excerpts, the full examples can be found in (#ExampleTypeMetadata).

The following is an example of an SD-JWT VC payload, containing a `vct` claim
with the value `https://betelgeuse.example.com/education_credential`:

```json
{
  "vct": "https://betelgeuse.example.com/education_credential",
  "vct#integrity": "sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=",
  ...
}
```

Type Metadata for the type `https://betelgeuse.example.com/education_credential`
can be retrieved using various mechanisms as described in
(#retrieving-type-metadata). For this example, the `vct` value is a URL as defined in
(#retrieval-from-vct-claim) and the following Type Metadata document is
retrieved from it:

```json
{
  "vct":"https://betelgeuse.example.com/education_credential",
  "name":"Betelgeuse Education Credential - Preliminary Version",
  "description":"This is our development version of the education credential. Don't panic.",
  "extends":"https://galaxy.example.com/galactic-education-credential-0.9",
  "extends#integrity":"sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU="
}
```


Note: The hash of the Type Metadata document shown in the second example must be equal
to the one in the `vct#integrity` claim in the SD-JWT VC payload,
`1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=`.

## Type Metadata Format {#type-metadata-format}

The Type Metadata document MUST be a JSON object. The following properties are
defined:

* `vct`: REQUIRED. The verifiable credential type described by this type metadata document.
* `name`: OPTIONAL. A human-readable name for the type, intended for developers reading
  the JSON document.
* `description`: OPTIONAL. A human-readable description for the type, intended for
  developers reading the JSON document.
* `extends`: OPTIONAL. A URI of another type that this type extends, as described in
  (#extending-type-metadata).
* `display`: An array of objects containing display information for the type, as described
  in (#display-metadata). This property is OPTIONAL.
* `claims`: An array of objects containing claim information for the type, as described in
  (#claim-metadata). This property is OPTIONAL.

A Type Metadata document MAY contain additional top level or subordinate properties.
Consumers MUST ignore properties that are not understood.

An example of a Type Metadata document is shown in (#ExampleTypeMetadata).

## Retrieving Type Metadata {#retrieving-type-metadata}

A consumer retrieving Type Metadata MUST ensure that the `vct` value in the
SD-JWT VC payload is identical to the `vct` value in the reference to the Type
Metadata (either in the SD-JWT VC itself or in an `extends` property in a Type
Metadata document).

The following sections define methods to retrieve Type Metadata.

### From a URL in the `vct` Claim {#retrieval-from-vct-claim}

A URI in the `vct` claim can be used to express a type. If the
type is a URL using the HTTPS scheme, Type Metadata MAY be retrieved from it.

The Type Metadata is retrieved using the HTTP GET method. The response MUST be a JSON
object as defined in (#type-metadata-format).

If the claim `vct#integrity` is present in the SD-JWT VC, its value
`vct#integrity` MUST be an "integrity metadata" string as defined in Section (#document-integrity).

### From a Registry {#retrieval-from-registry}

A Consumer MAY use a registry to retrieve Type Metadata for a SD-JWT VC type,
e.g., if the type is not an HTTPS URL or if the Consumer does not have
access to the URL. The registry MUST be a trusted registry, i.e., the Consumer MUST trust the registry to provide correct Type Metadata for the type.

The registry MUST provide the Type Metadata in the same format as described in
(#type-metadata-format).

### Using a Defined Retrieval Method {#defined-retrieval-method}

Ecosystems MAY define additional methods for retrieving Type Metadata. For example, a
standardization body or a community MAY define a service which has to be used to
retrieve Type Metadata based on a URN in the `vct` claim.

### From a Local Cache {#retrieval-from-local-cache}

A Consumer MAY cache Type Metadata for a SD-JWT VC type. If a hash for integrity
protection is present in the Type Metadata as defined in (#document-integrity), the Consumer MAY assume that the Type Metadata is static and can be cached
indefinitely. Otherwise, the Consumer MUST use the `Cache-Control`
header of the HTTP response to determine how long the metadata can be cached.

## Extending Type Metadata {#extending-type-metadata}

An SD-JWT VC type can extend another type. The extended type is identified by the URI in
the `extends` property. Consumers MUST retrieve and process
Type Metadata for the extended type before processing the Type Metadata for the extending
type.

The extended type MAY itself extend another type. This can be used to create a
chain or hierarchy of types. The security considerations described in
(#circular-extends) apply in order to avoid problems with circular dependencies.

# Document Integrity {#document-integrity}

The `vct` claim in the SD-JWT VC as defined in (#claims) and various URIs in the
Type Metadata MAY be accompanied by a respective claim suffixed with
`#integrity`, in particular:

 * `extends` as defined in (#extending-type-metadata), and
 * `uri` as used in two places in (#rendering-metadata).

The value MUST be an "integrity metadata" string as defined in Section 3 of
[@!W3C.SRI]. A Consumer of the respective documents MUST verify the
integrity of the retrieved document as defined in Section 3.3.5 of [@!W3C.SRI].

# Display Metadata {#display-metadata}

The `display` property is an array containing display information for the type.
The array MUST contain an object for each locale that is supported by the
type. The consuming application MUST use the language tag it considers most
appropriate for the user.

The objects in the array have the following properties:

- `locale`: A language tag as defined in Section 2 of [@!RFC5646]. This property is REQUIRED.
- `name`: A human-readable name for the type, intended for end users. This
  property is REQUIRED.
- `description`: A human-readable description for the type, intended for end
  users. This property is OPTIONAL.
- `rendering`: An object containing rendering information for the type, as
  described in (#rendering-metadata). This property is OPTIONAL.

## Rendering Metadata {#rendering-metadata}

The `rendering` property is an object containing rendering information for the
type. The object MUST contain a property for each rendering method that is
supported by the type. The property name MUST be a rendering method identifier
and the property value MUST be an object containing the properties defined for
the rendering method.

### Rendering Method "simple" {#rendering-method-simple}

The `simple` rendering method is intended for use in applications that do not
support SVG rendering. The object contains the following properties:

- `logo`: An object containing information about the logo to be displayed for
  the type, as described in (#logo-metadata). This property is OPTIONAL.
- `background_image`: An object containing information about the background image to be displayed for
  the type, as described in (#background-image-metadata). This property is OPTIONAL.
- `background_color`: An RGB color value as defined in [@!W3C.CSS-COLOR] for the background of the credential.
  This property is OPTIONAL.
- `text_color`: An RGB color value as defined in [@!W3C.CSS-COLOR] value for the text of the credential. This property
  is OPTIONAL.

#### Logo Metadata {#logo-metadata}

The `logo` property is an object containing information about the logo to be
displayed for the type. The object contains the following properties:

- `uri`: A URI pointing to the logo image. This property is REQUIRED.
- `uri#integrity`: An "integrity metadata" string as described in
  (#document-integrity). This property is OPTIONAL.
- `alt_text`: A string containing alternative text for the logo image. This
  property is OPTIONAL.

#### Background Image Metadata {#background-image-metadata}

The `background_image` property is an object containing information about the background image to be
displayed for the type. The object contains the following properties:

- `uri`: A URI pointing to the background image. This property is REQUIRED.
- `uri#integrity`: An "integrity metadata" string as described in
  (#document-integrity). This property is OPTIONAL.


### Rendering Method "svg_template" {#rendering-method-svg}

The `svg_template` rendering method is intended for use in applications that
support SVG rendering. The object MUST contain an array of objects containing
information about the SVG templates available for the type. Each object contains
the following properties:

- `uri`: A URI pointing to the SVG template. This property is REQUIRED.
- `uri#integrity`: An "integrity metadata" string as described in
  (#document-integrity). This property is OPTIONAL.
- `properties`: An object containing properties for the SVG template, as
  described in (#svg-template-properties). This property is REQUIRED if more than
  one SVG template is present, otherwise it is OPTIONAL.

#### SVG Template Properties {#svg-template-properties}

The `properties` property is an object containing properties for the SVG
template. Consuming applications MUST use these properties to find the best SVG
template available for display to the user based on the display properties
(landscape/portrait) and user preferences (color scheme, contrast). The object
MUST contain at least one of the following properties:

- `orientation`: The orientation for which the SVG template is optimized, with
  valid values being `portrait` and `landscape`. This property is OPTIONAL.
- `color_scheme`: The color scheme for which the SVG template is optimized, with
  valid values being `light` and `dark`. This property is OPTIONAL.
- `contrast`: The contrast for which the SVG template is optimized, with valid
  values being `normal` and `high`. This property is OPTIONAL.

#### SVG Rendering {#svg-rendering}

Consuming application MUST preprocess the SVG template by replacing placeholders
in the SVG template with properly escaped values of the claims in the credential. The
placeholders MUST be defined in the SVG template using the syntax
`{{svg_id}}`, where `svg_id` is an identifier defined in the claim metadata as
described in (#claim-metadata).

Placeholders MUST only be used in the text content of the SVG template and MUST NOT
be used in any other part of the SVG template, e.g., in attributes or comments.

A consuming application MUST ensure that all special characters in the claim
values are properly escaped before inserting them into the SVG template. At
least the following characters MUST be escaped:

- `&` as `&amp;`
- `<` as `&lt;`
- `>` as `&gt;`
- `"` as `&quot;`
- `'` as `&apos;`

If the `svg_id` is not present in the claim metadata, the consuming application
SHOULD reject not render the SVG template. If the `svg_id` is present in the
claim metadata, but the claim is not present in the credential, the placeholder
MUST be replaced with an empty string or a string appropriate to indicate that
the value is absent.

The following non-normative example shows a minimal SVG with one placeholder
using the `svg_id` value `address_street_address` which is defined in the
example in (#ExampleTypeMetadata):

```svg
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="10" y="20">Street address: {{address_street_address}}</text>
</svg>
```

When rendering the SVG template, the consuming application MUST ensure that
malicious metadata providers or issuers cannot inject executable code into the SVG
template and thereby compromise the security of the consuming application. The
consuming application MUST NOT execute any code in the SVG template. If code
execution cannot be prevented reliably, the SVG display MUST be sandboxed.

# Claim Metadata {#claim-metadata}

The `claims` property is an array of objects containing information about
particular claims for displaying and validating the claims.

The array MAY contain an object for each claim that is supported by the type.
Each object contains the following properties:

- `path`: An array indicating the claim or claims that are being addressed, as
  described below. This property is REQUIRED.
- `display`: An array containing display information for the claim or claims that are being addressed, as
  described in (#claim-display-metadata). This property is OPTIONAL.
- `mandatory`: A boolean indicating that the claim must be present in the issued
  credential. This property is OPTIONAL. If omitted, the default value is `false`. See
  (#claim-mandatory-metadata) for details.
- `sd`: A string indicating whether the claim is selectively disclosable, as
  described in (#claim-selective-disclosure-metadata). This property is OPTIONAL.
- `svg_id`: A string defining the ID of the claim for reference in the SVG
  template, as described in (#svg-rendering). The ID MUST be unique within the
  type metadata. It MUST consist of only alphanumeric characters and underscores
  and MUST NOT start with a digit. This property is OPTIONAL.

## Claim Path {#claim-path}

The `path` property MUST be a non-empty array of strings, `null` values, or
non-negative integers. It is used to select a particular claim in the credential
or a set of claims. A string indicates that the respective key is to be
selected, a `null` value indicates that all elements of the currently selected
array(s) are to be selected, and a non-negative integer indicates that the
respective index in an array is to be selected.

The following shows a non-normative, reduced example of a credential:

```json
{
  "vct": "https://betelgeuse.example.com/education_credential",
  "name": "Arthur Dent",
  "address": {
    "street_address": "42 Market Street",
    "city": "Milliways",
    "postal_code": "12345"
  },
  "degrees": [
    {
      "type": "Bachelor of Science",
      "university": "University of Betelgeuse"
    },
    {
      "type": "Master of Science",
      "university": "University of Betelgeuse"
    }
  ],
  "nationalities": ["British", "Betelgeusian"]
}
```

The following shows examples of `path` values and the respective selected
claims in the credential above:

- `["name"]`: The claim `name` with the value `Arthur Dent` is selected.
- `["address"]`: The claim `address` with its sub-claims as the value is selected.
- `["address", "street_address"]`: The claim `street_address` with the value
  `42 Market Street` is selected.
- `["degrees", null, "type"]`: All `type` claims in the `degrees` array are
  selected.

The example in (#ExampleTypeMetadata) shows how the `path` can be used to
address arrays and their elements.

In detail, the array is processed from left to right as follows:

 1. Select the root element of the credential, i.e., the top-level JSON object.
 2. Process the `path` components from left to right:
    1. If the `path` component is a string, select the element in the respective
       key in the currently selected element(s). If any of the currently
       selected element(s) is not an object, abort processing and return an
       error. If the key does not exist in any element currently selected,
       remove that element from the selection.
    2. If the `path` component is `null`, select all elements of the currently
       selected array(s). If any of the currently selected element(s) is not an
       array, abort processing and return an error.
    3. If the `path` component is a non-negative integer, select the element at
       the respective index in the currently selected array(s). If any of the
       currently selected element(s) is not an array, abort processing and
       return an error. If the index does not exist in a selected array, remove
       that array from the selection.
  3. If the set of elements currently selected is empty, abort processing and
     return an error.

The result of the processing is the set of elements to which the respective
claim metadata applies.

The `path` property MUST point to the respective claim as if all
selectively disclosable claims were disclosed to a Verifier. That means that a
consuming application which does not have access to all disclosures may not be
able to identify the claim which is being addressed.

Note: This specification intentionally does not use JSON Pointer [@?RFC6901] for
selecting claims, as JSON Pointer requires string parsing and does not support
wildcard selection of array elements. It does not use JSON Path [@?RFC9535] as
that introduces a considerable complexity and brings in many features which
are not needed for the use case of selecting claims in a credential. There are
also security concerns with some implementations.

## Claim Display Metadata {#claim-display-metadata}

The `display` property is an array containing display information for the
claim. The array MUST contain an object for each locale that is supported by
the type. The consuming application MUST use the language tag it considers most
appropriate for the user.

The objects in the array have the following properties:

- `locale`: A language tag as defined in Section 2 of [@!RFC5646]. This property is REQUIRED.
- `label`: A human-readable label for the claim, intended for end users. This
  property is REQUIRED.
- `description`: A human-readable description for the claim, intended for end
  users. This property is OPTIONAL.

## Claim Mandatory Metadata {#claim-mandatory-metadata}

The `mandatory` property is a boolean indicating that, if set to `true`, the
claim MUST be included in the credential by the Issuer. If the value is `false`
or omitted, the claim is considered optional for the Issuer to include. A claim
that is `mandatory` can nonetheless be selectively disclosable, as described in
(#claim-selective-disclosure-metadata).

## Claim Selective Disclosure Metadata {#claim-selective-disclosure-metadata}

The `sd` property is a string indicating whether the claim is selectively
disclosable. The following values are defined:

- `always`: The Issuer MUST make the claim selectively disclosable.
- `allowed`: The Issuer MAY make the claim selectively disclosable.
- `never`: The Issuer MUST NOT make the claim selectively disclosable.

If omitted, the default value is `allowed`. It is RECOMMENDED to use
either `always` or `never` to avoid ambiguity.

## Extending Claim Metadata {#claim-metadata-extends}

The `extends` property allows a type to inherit claim metadata from another type. When present, all claim metadata from the extended type MUST be respected and are inherited by the child type. The child type can extend the claim metadata by adding new claims or properties. If the child type defines claim metadata with the same `path` as in the extended type, the child type's object will override the corresponding object from the extended type.

An extending type can specify an `sd` property for a claim that is marked as
`allowed` in the extended type (or where `sd` was omitted), changing it to either `always` or `never`.
However, it MUST NOT change a claim that is marked as `always` or `never` in the extended
type to a different value.

Similarly, an extending type can set the `mandatory` property of a claim that is
optional in the extended type to `true`, but it MUST NOT change a claim that is
`mandatory` in the extended type to `false`.

Suppose we have a base type metadata document:

```json
{
  "vct": "https://example.com/base-type-metadata",
  "claims": [
    {
      "path": ["name"],
      "display": [{"label": "Full Name", "locale": "en"}]
    },
    {
      "path": ["address", "city"],
      "display": [{"label": "City", "locale": "en"}]
    }
  ]
}
```

And a child type metadata document that extends the base type:

```json
{
  "vct": "https://example.com/custom-type-metadata",
  "extends": "https://example.com/base-type-metadata",
  "claims": [
    {
      "path": ["address", "city"],
      "display": [{"label": "Town", "locale": "en"}]
    },
    {
      "path": ["nationalities"],
      "display": [{"label": "Nationalities", "locale": "en"}]
    }
  ]
}
```

In this example, the child type inherits the `name` claim metadata from the base type, but overrides the `address.city` claim metadata with its own definition. It also adds a new claim metadata for `nationalities`. The final effective claim metadata for the child type is:

```json
{
  "claims": [
    {
      "path": ["name"],
      "display": [{"label": "Full Name", "locale": "en"}]
    },
    {
      "path": ["address", "city"],
      "display": [{"label": "Town", "locale": "en"}]
    },
    {
      "path": ["nationalities"],
      "display": [{"label": "Nationalities", "locale": "en"}]
    }
  ]
}
```

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

When defining ecosystem-specific rules for resolution and verification of the public key,
as outlined in (#ism), it is critical that those rules maintain the integrity of the
relationship between the `iss` value of the SD-JWT, if present, and the public keys of the Issuer.

It MUST be ensured that for any given `iss` value, an attacker cannot influence
the type of verification process used. Otherwise, an attacker could attempt to make
the Verifier use a verification process not intended by the Issuer, allowing the
attacker to potentially manipulate the verification result to their advantage.

## Circular "extends" Dependencies of Types {#circular-extends}

A type MUST NOT extend another type that extends (either directly or with steps
in-between) the first type. This would result in a circular dependency that
could lead to infinite recursion when retrieving and processing the metadata.

Consumers MUST detect such circular dependencies and reject the
credential.

## Robust Retrieval of Type Metadata {#robust-retrieval}

In (#retrieving-type-metadata), various methods for distributing and retrieving
metadata are described. Methods relying on a network connection may fail due to
network issues or unavailability of a network connection due to offline usage of
credentials, temporary server outages, or denial-of-service attacks on the
metadata server.

Consumers SHOULD therefore implement a local cache as described in
(#retrieval-from-local-cache) if possible. Such a cache MAY be populated with metadata before
the credential is used.

These measures allow the Consumers to continue to function even if
the metadata server is temporarily unavailable and avoid privacy issues as
described in (#privacy-preserving-retrieval-of-type-metadata).

## Risks Associated with Textual Information {#risks-textual-information}

Some claims in the SD-JWT VC and properties in the Type Metadata, e.g., `display`, allows issuers and providers of metadata to
specify human-readable information. These can contain arbitrary textual information that
may be displayed to end users and developers. As such, any consuming application MUST ensure that maliciously
crafted information cannot be used to compromise the security of the application
or the privacy of the user. To this end, the following considerations apply:

- The consuming application MUST ensure that the text is properly escaped before
  displaying it to the user or transferring it into other contexts. For example,
  if the data is displayed in an HTML document, the text MUST be properly
  escaped to prevent Cross-Site Scripting (XSS) attacks.
- The consuming application MUST ensure that the display of the user interface
  elements cannot be distorted by overly long text or special characters.

## Credential Type Extension and Issuer Authorization {#type-extension-issuer-authorization}

When processing credentials, it is important to recognize that the ability to extend or reference
an existing credential type (e.g., a well-known identifier such as `urn:ec.eu.x.y.z`) does not
confer any implicit authorization to issue credentials of that type or its extensions. In particular:

- **Issuer Authorization**: Verifiers and wallets MUST NOT assume that any issuer who issues a credential extending a known type is authorized to do so. The mere presence of an extension or reference to a recognized type (e.g., a national type `urn:de.bla` extending a European PID type) does not validate the issuer's authority.
- **Rogue Issuers**: Attackers may issue credentials with types that extend or mimic legitimate types (e.g., `urn:attacker` extending `urn:ec.eu.x.y.z`). Such credentials MUST NOT be accepted solely based on their type hierarchy or extension relationship.
- **Processing Rules**: Implementations MUST verify the issuer's authorization independently of the credential type or its extensions. This typically involves checking the issuer's identity, trust status, and any relevant accreditation or registry before accepting a credential.

**Recommendation:**
Verifiers and wallets SHOULD implement explicit checks for issuer authorization and SHOULD NOT rely on type extension as a proxy for trust or legitimacy. Credential acceptance decisions MUST be based on both the credential type and the verified authority of the issuer.

## Trust in Type Metadata

Type Metadata associated with an SD-JWT VC, e.g., rendering metadata, is asserted by the publisher of the Type Metadata and trust in this metadata depends on the trust relationship between its publisher and the consumer. A consumer MUST NOT assume that Type Metadata is accurate or meaningful unless the publisher is recognized as authoritative for the type in question.

Ecosystems SHOULD define governance or accreditation mechanisms that specify which publishers are authorized to provide Type Metadata for specific verifiable credential types and under what conditions such metadata can be relied upon.

Consumers SHOULD treat with reduced trust any Type Metadata if the publisher is not accredited or otherwise trusted within the applicable ecosystem.

## Use of Data URIs for Claim Types

The use of data URIs allows embedding of data directly within credential payloads. Implementations SHOULD treat data URIs as untrusted input at the processing and rendering layer and apply appropriate validation and handling. Failure to properly escape, sanitize or constrain their use can lead to security issues such as unintended code execution, resource exhaustion, or misuse of embedded content. Implementations SHOULD restrict the set of accepted media types, enforce reasonable size and content limits, and avoid dereferencing or interpreting data URIs in ways that could execute or render active content, consistent with their overall security model.

# Privacy Considerations {#privacy-considerations}

The Privacy Considerations in the SD-JWT specification
[@!I-D.ietf-oauth-selective-disclosure-jwt] apply to this specification.
Additionally, the following privacy considerations need to be taken into
account when using SD-JWT VCs.

## Unlinkability

The Privacy Considerations in Section 10.1 of [@!I-D.ietf-oauth-selective-disclosure-jwt]
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
The Verifier would create an HTTP GET request to the Holder-specific well-known URI
when the SD-JWT VC is verified. This would allow the malicious Issuer to keep track where
and how often the SD-JWT VC was used.

Verifiers are advised to establish trust in an SD-JWT VC by pinning specific Issuer identifiers
and should monitor suspicious behavior such as frequent rotation of those identifiers.
If such behaviour is detected, Verifiers are advised to reject SD-JWT VCs issued by those
Issuers.

Another related concern arises from the use of confirmation methods in the cnf claim that involve retrieving key material from a remote source, especially if that source is controlled by the issuer. This includes, but is not limited to, the use of the x5u parameter in JWKs ([@!RFC7517, section 4.6]), the jku parameter ([@!RFC7800, section 3.5]), and cases where a URL is used in the kid parameter ([@!RFC7800, section 3.4]). Future confirmation methods may also introduce remote retrieval mechanisms. Issuers are advised not to issue SD-JWT VCs with such cnf methods, and Verifiers and Holders are advised not to follow or resolve remote references for key material in the cnf claim. Only confirmation methods that do not require remote retrieval of key material SHOULD be supported.

Holders are advised to reject SD-JWT VCs if they contain easily correlatable information
in the Issuer identifier.

# Relationships to Other Documents

This specification defines validation and processing rules for verifiable credentials using JSON
payloads and secured by SD-JWT [@!I-D.ietf-oauth-selective-disclosure-jwt]. Other specifications exist
that define their own verifiable credential formats; for example, W3C Verifiable
Credential Data Model (VCDM) 2.0 [@W3C.VCDM] defines a data model for verifiable credentials encoded as JSON-LD, and
ISO/IEC 18013-5:2021 [@ISO.18013-5] defines a representation of verifiable credentials in the mobile document (mdoc)
format encoded as CBOR and secured using COSE.

## Privacy-Preserving Retrieval of Type Metadata {#privacy-preserving-retrieval-of-type-metadata}

In (#retrieving-type-metadata), various methods for distributing and retrieving
Type Metadata are described. For methods which rely on a network connection to a
URL (e.g., provided by an Issuer), the Issuer and other third parties may be able
to track the usage of a credential by observing requests to the Type Metadata URL.

Consumers SHOULD prefer methods for retrieving Type Metadata that do not
leak information about the usage of a credential to third parties. The
recommendations in (#robust-retrieval) apply.

<reference anchor="IANA.well-known" target="https://www.iana.org/assignments/well-known-uris">
    <front>
      <title>Well-Known URIs</title>
      <author>
        <organization>IANA</organization>
      </author>
    <date/>
    </front>
</reference>

<reference anchor="OWASP_SSRF" target="https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html/">
  <front>
    <author fullname="OWASP"></author>
    <title>Server Side Request Forgery Prevention Cheat Sheet</title>
  </front>
</reference>

<reference anchor="W3C.SRI" target="https://www.w3.org/TR/SRI/">
    <front>
        <author initials="D." surname="Akhawe" fullname="Devdatta Akhawe">
            <organization>
                <organizationName>Dropbox, Inc.</organizationName>
            </organization>
        </author>
        <author initials="F." surname="Braun" fullname="Frederik Braun">
            <organization>
                <organizationName>Mozilla</organizationName>
            </organization>
        </author>
        <author initials="F." surname="Marier" fullname="François Marier">
            <organization>
                <organizationName>Mozilla</organizationName>
            </organization>
        </author>
        <author initials="J." surname="Weinberger" fullname="Joel Weinberger">
            <organization>
                <organizationName>Google, Inc.</organizationName>
            </organization>
        </author>
        <title>Subresource Integrity</title>
        <date day="23" month="June" year="2016"/>
    </front>
</reference>

<reference anchor="W3C.VCDM" target="https://www.w3.org/TR/vc-data-model-2.0/">
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
        <author initials="D." surname="Chadwick" fullname="David Chadwick">
            <organization>
                <organizationName>Crossword Cybersecurity PLC</organizationName>
            </organization>
        </author>
        <author initials="O." surname="Steele" fullname="Orie Steele">
            <organization>
                <organizationName>Transmute</organizationName>
            </organization>
        </author>
        <title>Verifiable Credentials Data Model v2.0</title>
        <date day="10" month="February" year="2024"/>
    </front>
</reference>

<reference anchor="ISO.18013-5" target="https://www.iso.org/standard/69084.html">
    <front>
        <title>ISO/IEC 18013-5:2021</title>
        <date day="1" month="September" year="2024"/>
        <author>
            <organization>ISO/IEC</organization>
        </author>
    </front>
</reference>

<reference anchor="EUDIW.ARF" target="https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/releases">
  <front>
    <author fullname="European Commission"></author>
    <title>The European Digital Identity Wallet Architecture and Reference Framework</title>
  </front>
</reference>

<reference anchor="W3C.CSS-COLOR" target="https://www.w3.org/TR/css-color-3">
  <front>
    <title>CSS Color Module Level 3</title>
    <date day="18" month="January" year="2022"/>
    <author initials="T." surname="Çelik" fullname="Tantek Çelik">
      <organization>
        <organizationName>Mozilla Corporation</organizationName>
      </organization>
    </author>
    <author initials="C." surname="Lilley" fullname="Chris Lilley">
      <organization>
        <organizationName>W3C</organizationName>
      </organization>
    </author>
    <author initials="L. D." surname="Baron" fullname="L. David Baron">
      <organization>
        <organizationName>W3C Invited Experts</organizationName>
      </organization>
    </author>
  </front>
</reference>

{backmatter}

# IANA Considerations

## JSON Web Token Claims Registration

- Claim Name: "vct"
- Claim Description: Verifiable credential type identifier
- Change Controller: IETF
- Specification Document(s): [[ (#type-claim) of this specification ]]

- Claim Name: "vct#integrity"
- Claim Description: SD-JWT VC vct claim "integrity metadata" value
- Change Controller: IETF
- Specification Document(s): [[ (#document-integrity) of this specification ]]

## Media Types Registry

### application/dc+sd-jwt {#media-type}

The Internet media type for an SD-JWT VC is `application/dc+sd-jwt`.

* Type name: `application`
* Subtype name: `dc+sd-jwt`
* Required parameters: n/a
* Optional parameters: n/a
* Encoding considerations: 8-bit code points; SD-JWT VC values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') and tilde ('~') characters.
* Security considerations: See Security Considerations in (#security-considerations).
* Interoperability considerations: n/a
* Published specification: [[ this specification ]]
* Applications that use this media type: Applications that issue, present, and verify SD-JWT-based verifiable credentials.
* Additional information:
  - Magic number(s): n/a
  - File extension(s): n/a
  - Macintosh file type code(s): n/a
* Person & email address to contact for further information: Oliver Terbu <oliver.terbu@mattr.global>
* Intended usage: COMMON
* Restrictions on usage: none
* Author: Oliver Terbu <oliver.terbu@mattr.global>
* Change controller: IETF

## Well-Known URI Registry

This specification requests the well-known URI defined in (#jwt-vc-issuer-metadata)
in the IANA "Well-Known URIs" registry [@IANA.well-known] established
by [@!RFC5785].

### Registry Contents

* URI suffix: jwt-vc-issuer
* Change controller: IETF
* Specification document: [[ (#jwt-vc-issuer-metadata) of this specification ]]
* Related information: (none)
* Status: permanent

# Examples

Important: The following examples are not normative and provided for
illustrative purposes only. In particular, neither the structure of the claims
nor the selection of selectively disclosable claims are normative.

Line breaks have been added for readability.

## Example 1: Person Identification Data (PID) Credential

This example shows how the artifacts defined in this specification could be used
to represent the concept of a Person Identification Data (PID) as defined in the
"PID Rulebook" in [@EUDIW.ARF]. This example uses fictional data of a German
citizen.

Key Binding is applied
using the Holder's public key passed in a `cnf` claim in the SD-JWT.

The following data about the citizen comprises the input JWT Claims Set used by the Issuer:

<{{examples/03-pid/user_claims.json}}

The following is the issued SD-JWT:

<{{examples/03-pid/sd_jwt_issuance.txt}}

This is the payload of that SD-JWT:

<{{examples/03-pid/sd_jwt_payload.json}}

The digests in the SD-JWT payload reference the following Disclosures:

{{examples/03-pid/disclosures.md}}

This shows a presentation of the SD-JWT with a Key Binding JWT that discloses only nationality and the fact that the person is over 18 years old:

<{{examples/03-pid/sd_jwt_presentation.txt}}

The following is the payload of a corresponding Key Binding JWT:

<{{examples/03-pid/kb_jwt_payload.json}}

After validation, the Verifier will have the following processed SD-JWT payload available for further handling:

<{{examples/03-pid/verified_contents.json}}

## Example 2: Type Metadata {#ExampleTypeMetadata}

The following example for Type Metadata assumes an SD-JWT VC payload structured as follows:

```json
{
  "vct": "https://betelgeuse.example.com/education_credential",
  "vct#integrity": "sha256-1odmyxoVQCuQx8SAym8rWHXba41fM/Iv/V1H8VHGN00=",
  "name": "Zaphod Beeblebrox",
  "address": {
    "street_address": "42 Galaxy Way",
    "city": "Betelgeuse City",
    "postal_code": "12345",
    "country": "Betelgeuse"
  },
  "degrees": [
    {
      "field_of_study": "Intergalactic Politics",
      "date_awarded": "2020-05-15"
    },
    {
      "field_of_study": "Space Navigation",
      "date_awarded": "2018-06-20"
    },
    {
      "field_of_study": "Quantum Mechanics",
      "date_awarded": "2016-07-25"
    }
  ]
}
```

The Type Metadata for this SD-JWT VC could be defined as follows:

```json
{
  "vct": "https://betelgeuse.example.com/education_credential",
  "name": "Betelgeuse Education Credential - Preliminary Version",
  "description": "This is our development version of the education credential. Don't panic.",
  "extends": "https://galaxy.example.com/galactic-education-credential-0.9",
  "extends#integrity": "sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=",
  "display": [
    {
      "locale": "en-US",
      "name": "Betelgeuse Education Credential",
      "description": "An education credential for all carbon-based life forms on Betelgeusians",
      "rendering": {
        "simple": {
          "logo": {
            "uri": "https://betelgeuse.example.com/public/education-logo.png",
            "uri#integrity": "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=",
            "alt_text": "Betelgeuse Ministry of Education logo"
          },
          "background_image": {
            "uri": "https://betelgeuse.example.com/public/credential-background.png",
            "uri#integrity": "sha256-5sBT7mMLylHLWrrS/qQ8aHpRAxoraWVmWX6eUVMlrrA="
          },
          "background_color": "#12107c",
          "text_color": "#FFFFFF"
        },
        "svg_templates": [
          {
            "uri": "https://betelgeuse.example.com/public/credential-english.svg",
            "uri#integrity": "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=",
            "properties": {
              "orientation": "landscape",
              "color_scheme": "light",
              "contrast": "high"
            }
          }
        ]
      }
    },
    {
      "locale": "de-DE",
      "name": "Betelgeuse-Bildungsnachweis",
      "rendering": {
        "simple": {
          "logo": {
            "uri": "https://betelgeuse.example.com/public/education-logo-de.png",
            "uri#integrity": "sha256-LmXfh+9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1U=",
            "alt_text": "Logo des Betelgeusischen Bildungsministeriums"
          },
          "background_image": {
            "uri": "https://betelgeuse.example.com/public/credential-background-de.png",
            "uri#integrity": "sha256-9cLlJNXN+TsMk+PmKjZ5t0WRL5ca/xGgX3c1ULmXfh="
          },
          "background_color": "#12107c",
          "text_color": "#FFFFFF"
        },
        "svg_templates": [
          {
            "uri": "https://betelgeuse.example.com/public/credential-german.svg",
            "uri#integrity": "sha256-I4JcBGO7UfrkOBrsV7ytNJAfGuKLQh+e+Z31mc7iAb4=",
            "properties": {
              "orientation": "landscape",
              "color_scheme": "light",
              "contrast": "high"
            }
          }
        ]
      }
    }
  ],
  "claims": [
    {
      "path": ["name"],
      "display": [
        {
          "locale": "de-DE",
          "label": "Vor- und Nachname",
          "description": "Der Name des Studenten"
        },
        {
          "locale": "en-US",
          "label": "Name",
          "description": "The name of the student"
        }
      ],
      "sd": "always",
      "mandatory": true
    },
    {
      "path": ["address"],
      "display": [
        {
          "locale": "de-DE",
          "label": "Adresse",
          "description": "Adresse zum Zeitpunkt des Abschlusses"
        },
        {
          "locale": "en-US",
          "label": "Address",
          "description": "Address at the time of graduation"
        }
      ],
      "sd": "always"
    },
    {
      "path": ["address", "street_address"],
      "display": [
        {
          "locale": "de-DE",
          "label": "Straße"
        },
        {
          "locale": "en-US",
          "label": "Street Address"
        }
      ],
      "sd": "always",
      "svg_id": "address_street_address"
    },
    {
      "path": ["degrees"],
      "display": [
        {
          "locale": "de-DE",
          "label": "Abschlüsse",
          "description": "Abschlüsse des Studenten"
        },
        {
          "locale": "en-US",
          "label": "Degrees",
          "description": "Degrees earned by the student"
        }
      ],
      "sd": "never"
    },
    {
      "path": ["degrees", null],
      "sd": "always"
    },
    {
      "path": ["degrees", null, "field_of_study"],
      "display": [
        {
          "locale": "de-DE",
          "label": "Studienfach"
        },
        {
          "locale": "en-US",
          "label": "Field of Study"
        }
      ],
      "sd": "never"
    },
    {
      "path": ["degrees", null, "date_awarded"],
      "display": [
        {
          "locale": "de-DE",
          "label": "Verleihungsdatum"
        },
        {
          "locale": "en-US",
          "label": "Date Awarded"
        }
      ],
      "sd": "always"
    }
  ]
}
```

Note that in this example, there are four definitions affecting the `degrees` claim:

1. The `degrees` array itself is marked as `sd: never`, meaning the element `degrees` cannot be selectively disclosed and will always exist in the disclosed SD-JWT. Changing this to `sd: always` would mean that the `degrees` array itself is selectively disclosable.
2. Each item in the `degrees` array (denoted by `null` in the path) is marked as `sd: always`, meaning each degree object will be selectively disclosed as a whole.
3. The `field_of_study` property of each degree object is marked as `sd: never`, meaning that if the respective degree object is disclosed, the `field_of_study` property will always be included and cannot be hidden.
4. The `date_awarded` property of each degree object is marked as `sd: always`, meaning it can be selectively disclosed.


# Acknowledgements {#Acknowledgements}

We would like to thank
Aaron Parecki,
Alen Horvat,
Andres Uribe,
Andrii Deinega,
Babis Routis,
Christian Bormann,
Denis Pinkas,
George J Padayatti,
Giuseppe De Marco,
Lukas J Han,
Leif Johansson,
Michael B. Jones,
Mike Prorock,
Mirko Mollik,
Orie Steele,
Paul Bastian,
Pavel Zarecky,
Stefan Charsley,
Tim Cappalli,
Timo Glastra,
Torsten Lodderstedt,
Tobias Looker, and
Kristina Yasuda
for their contributions (some of which substantial) to this draft and to the initial set of implementations.

# Document History

-12

* Change `lang` to `locale`. While `lang` is more accurate, `locale` is what has traditionally been used in OpenID Connect and later related specs.
* Remove JSON schema from Type Metadata
* Introduce optional mandatory property for claims
* Explicitly mention that Type Metadata can have additional stuff that has to be ignored if not understood
* Clarify that an SD-JWT VC doesn't contain a KB-JWT but rather might have an associated one (which makes it a SD-JWT+KB and Brian is still not sure about the term or these words, but it's where we've ended up)
* Remove the requirement to ignore unknown claims, as some applications may not want to follow this rule
* Fix cnf claim and JWK references and move them to normative
* List `vct` as one of the required values in type metadata and ensure that the use of the document integrity claims is clear
* Remove discussion of status and Status Provider from the Introduction
* Add a background_image property to the simple rendering aligned with the definition in OpenID4VCI
* Recommend to use `sd=always` or `sd=never` to avoid ambiguity and introduce rules for `sd` and `mandatory` when extending types
* Provide some guidance on versioning via the `vct` value
* Add security considerations for trust in type metadata
* Require data URIs for non-JSON types
* Require `x5c` to be in the protected header
* Clarify presentations of SD-JWT VC do not require KB
* Updated/expanded example for Type Metadata
* Be more consistent with style for lists of claims/parameters/properties

-11

* Clarify extend support for claim metadata
* Add privacy concerns regarding the use of `x5u` parameter in JWKs and similar remote retrieval mechanisms
* Added a section on Credential Type Extension and Issuer Authorization.
* Fixed an inconsistency to the description of `display` attribute of claim metadata.
* add `vct#integrity` to the list of claims that cannot be selectively disclosed
* Drop explicit treatment of the glue type metadata document concept
* Editorial updates and fixes.
* State that when the `status` claim is present and using the `status_list` mechanism, the associated Status List Token has to be a JWT.
* `vct` datatype is now just a string

-10

* Rename 'Issuer-signed JWT Verification Key Validation' to 'Issuer Signature Mechanisms' and rework some text accordingly. Provide a web-based metadata resolution mechanism and an inline x509 mechanism. A DID-based mechanism is not explicitly provided herein but still possible via profile/extension. Be explicit that the employed Issuer Signature Mechanism has to be one that is permitted for the Issuer according to policy. Be more clear that one permitted Issuer Signature Mechanism is sufficient.
* Fix `[...]#integrity` claim values in examples (Subresource Integrity uses regular base64 encoding and some were wrong length)

-09

* Use SD-JWT KB in place of SD-JWT with Key Binding JWT
* Editorial changes
* Document reasons for not using JSON Pointer or JSON Path (Issue #267)
* Clarify that private claim names MAY be used
* Update PID Example
* Fix section numbering in a few SD-JWT references

-08

* Fix formatting issue introduced by the reintroduction of the DID paragraph in -07

-07

* Revert change from previous release that removed explicit mention of DIDs in the Issuer-signed JWT Verification Key Validation section
* Remove the requirement to insert a .well-known part for vct URLs
* fix section numbering in SD-JWT references to align with the latest -14 version

-06

* Update the anticipated media type registration request from `application/vc+sd-jwt` to `application/dc+sd-jwt`
* Tightened the exposition of the Issuer-signed JWT Verification Key Validation section
* Add the “Status” field for the well-known URI registration per IANA early review

-05

* Include display and claim type metadata
* Added example for type metadata
* Clarify, add context, or otherwise improved the examples

-04

* update reference to IETF Status List
* Include Type Metadata
* Include schema Type Metadata
* Editorial changes
* Updated terminology to clarify digital signatures are one way to secure VCs and presentations
* Rework key resolution/validation for x5c


-03

*  Include disclosure of age_equal_or_over/18 in the PID example

-02

* Made specific rules for public verification key validation conditional
* Finetuned rules for obtaining public verification key
* Editorial changes
* added Brian Campbell as co-author
* Renamed JWT Issuer Metadata to JWT VC Issuer Metadata
* 'iat' is now optional and allowed to be selectively disclosable
* Fix inconstancy in the .well-known path construction
* Added registration request to IANA for the well-known URI
* Fix some formatting and text in the media type and JWT claim registration requests
* Clarify the optionality of the `cnf` claim
* Added relationships to other documents
* Added PID example

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
