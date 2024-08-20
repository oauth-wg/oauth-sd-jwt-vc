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

This specification uses the terms "Holder", "Issuer", "Verifier", "Key Binding", and "Key Binding JWT" defined by
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

#### Registered JWT Claims {#claims}

SD-JWT VCs MAY use any claim registered in the "JSON Web Token Claims"
registry as defined in [@!RFC7519].

If present, the following registered JWT claims MUST be included in the SD-JWT
and MUST NOT be included in the Disclosures, i.e. cannot be selectively
disclosed:

* `iss`
    * REQUIRED. The Issuer of the Verifiable Credential. The value of `iss`
MUST be a URI. See [@!RFC7519] for more information.
* `nbf`
    * OPTIONAL. The time before which the Verifiable Credential MUST NOT be
accepted before validating. See [@!RFC7519] for more information.
* `exp`
    * OPTIONAL. The expiry time of the Verifiable Credential after which the
Verifiable Credential is no longer valid. See [@!RFC7519] for more
information.
* `cnf`
    * OPTIONAL unless cryptographic Key Binding is to be supported, in which case it is REQUIRED. Contains the confirmation method identifying the proof of possession key as defined in [@!RFC7800]. It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of [@!RFC7800]. For proof of cryptographic Key Binding, the Key Binding JWT in the presentation of the SD-JWT MUST be secured by the key identified in this claim.
* `vct`
    * REQUIRED. The type of the Verifiable Credential, e.g.,
`https://credentials.example.com/identity_credential`, as defined in (#type-claim).
* `status`
    * OPTIONAL. The information on how to read the status of the Verifiable
Credential. See [@!I-D.ietf-oauth-status-list]
 for more information.

The following registered JWT claims MAY be contained in the SD-JWT or in the
Disclosures and MAY be selectively disclosed:

* `sub`
    * OPTIONAL. The identifier of the Subject of the Verifiable Credential.
The Issuer MAY use it to provide the Subject
identifier known by the Issuer. There is no requirement for a binding to
exist between `sub` and `cnf` claims.
* `iat`
    * OPTIONAL. The time of issuance of the Verifiable Credential. See
      [@!RFC7519] for more information.

#### Public JWT claims

Additional public claims MAY be used in SD-JWT VCs depending on the
application.

#### SD-JWT VC without Selectively Disclosable Claims

An SD-JWT VC MAY have no selectively disclosable claims.
In that case, the SD-JWT VC MUST NOT contain the `_sd` claim in the JWT body. It also
MUST NOT have any Disclosures.

## Example {#vc-sd-jwt-example}

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

Furthermore, the recipient of the SD-JWT VC MUST validate the public verification key
for the Issuer-signed JWT as defined in (#issuer-signed-jwt-verification-key-validation).

If a schema is provided in the Type Metadata, a recipient MUST validate the schema as defined in (#schema-type-metadata).

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
- X.509 Certificates: If the recipient supports X.509 Certificates and the `iss` value contains an HTTPS URI, the recipient MUST
     1. obtain the public key from the end-entity certificate of the certificates from the `x5c` header parameter of the Issuer-signed JWT and validate the X.509 certificate chain accordingly, and
     2. ensure that the `iss` value matches a `uniformResourceIdentifier` SAN entry of the end-entity certificate or that the domain name in the `iss` value matches the `dNSName` SAN entry of the end-entity certificate.
- DID Document Resolution: If a recipient supports DID Document Resolution and if the `iss` value contains a DID [@W3C.DID], the recipient MUST retrieve the public key from the DID Document resolved from the DID in the `iss` value. In this case, if the `kid` JWT header parameter is present, the `kid` MUST be a relative or absolute DID URL of the DID in the `iss` value, identifying the public key.

Separate specifications or ecosystem regulations MAY define rules complementing the rules defined above, but such rules are out of scope of this specification. See (#ecosystem-verification-rules) for security considerations.

If a recipient cannot validate that the public verification key corresponds to the `iss` value of the Issuer-signed JWT, the SD-JWT VC MUST be rejected.

# Presenting Verifiable Credentials

This section defines encoding, validation and processing rules for presentations
of SD-JWT VCs.

## Key Binding JWT

If the presentation of the SD-JWT VC includes a Key Binding JWT, the Key Binding
JWT MUST adhere to the rules defined in Section 5.3 of
[@!I-D.ietf-oauth-selective-disclosure-jwt].

The Key Binding JWT MAY include additional claims which, when not understood, MUST
be ignored by the Verifier.

## Examples

The following is a non-normative example of a presentation of the SD-JWT shown in (#vc-sd-jwt-example) including a Key Binding JWT.
In this presentation, the Holder provides only the Disclosure for the  `address` claim.
Other claims are not disclosed to the Verifier.

<{{examples/01/sd_jwt_presentation.txt}}

The following example shows a presentation of a (different) SD-JWT without a
Key Binding JWT:

<{{examples/02/sd_jwt_presentation.txt}}

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

The following is a non-normative example of a HTTP request for the JWT VC Issuer
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

* `issuer`
    * REQUIRED. The Issuer identifier, which MUST be identical to the `iss`
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

The `issuer` value returned MUST be identical to the `iss` value of the
JWT. If these values are not identical, the data contained in the response
MUST NOT be used.

# Type Metadata {#type-metadata}

An SD-JWT VC type, i.e., the `vct` value, is associated with Type Metadata defining, for example, information about the type or a schema defining (see (#schema-definition)) which claims MAY or MUST appear in the SD-JWT VC.

This section defines Type Metadata that can be associated with a type of a SD-JWT VC, as well as a method for retrieving the Type Metadata and processing rules. This Type Metadata is intended to be used, among other things, for the following purposes:

 * Developers of Issuers and Verifiers can use the Type Metadata to understand the
   semantics of the type and the associated rules. While in some cases,
   Issuers are the parties that define types, this is
   not always the case. For example, a type can be defined by a
   standardization body or a community.
 * Verifiers can use the Type Metadata to determine whether a credential is valid
   according to the rules of the type. For example, a Verifier can check
   whether a credential contains all required claims and whether the claims
   are selectively disclosable.

Type Metadata can be retrieved as described in (#retrieving-type-metadata).

## Type Metadata Example {#type-metadata-example}

All examples in this section are non-normative.

The following is an example of an SD-JWT VC payload, containing a `vct` claim
with the value `https://betelgeuse.example.com/education_credential`:

```json
{
  "vct": "https://betelgeuse.example.com/education_credential",
  "vct#integrity": "sha256-WRL5ca_xGgX3c1VLmXfh-9cLlJNXN-TsMk-PmKjZ5t0",
  ...
}
```

Type Metadata for the type `https://betelgeuse.example.com/education_credential`
can be retrieved using various mechanisms as described in
(#retrieving-type-metadata). For this example, the well-known URL as defined in
(#retrieval-from-vct-claim) is used and the following Type Metadata Document is
retrieved from the URL
`https://betelgeuse.example.com/.well-known/vct/education_credential`:

```json
{
  "vct":"https://betelgeuse.example.com/education_credential",
  "name":"Betelgeuse Education Credential - Preliminary Version",
  "description":"This is our development version of the education credential. Don't panic.",
  "extends":"https://galaxy.example.com/galactic-education-credential-0.9",
  "extends#integrity":"sha256-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-WRL5",
  "schema_uri":"https://exampleuniversity.com/public/credential-schema-0.9",
  "schema_uri#integrity":"sha256-o984vn819a48ui1llkwPmKjZ5t0WRL5ca_xGgX3c1VLmXfh"
}
```

This example is shortened for presentation, a full Type Metadata example can be found in (#ExampleTypeMetadata).

Note: The hash of the Type Metadata document shown in the second example must be equal
to the one in the `vct#integrity` claim in the SD-JWT VC payload,
`WRL5ca_xGgX3c1VLmXfh-9cLlJNXN-TsMk-PmKjZ5t0`.

## Type Metadata Format {#type-metadata-format}

The Type Metadata document MUST be a JSON object. The following properties are
defined:

* `name`
  * OPTIONAL. A human-readable name for the type, intended for developers reading
  the JSON document.
* `description`
  * OPTIONAL. A human-readable description for the type, intended for
  developers reading the JSON document.
* `extends`
  * OPTIONAL. A URI of another type that this type extends, as described in
  (#extending-type-metadata).
* `display`: An object containing display information for the type, as described
  in (#display-metadata). This property is OPTIONAL.
* `claims`: An object containing claim information for the type, as described in
  (#claim-metadata). This property is OPTIONAL.
* `schema`
  * OPTIONAL. An embedded JSON Schema document describing the structure of
  the Verifiable Credential as described in (#schema-definition). `schema` MUST NOT be used
  if `schema_uri` is present.
* `schema_uri`
  * OPTIONAL. A URL pointing to a JSON Schema document describing the structure
  of the Verifiable Credential as described in (#schema-definition). `schema_uri` MUST NOT
  be used if `schema` is present.

An example of a Type Metadata document is shown in (#ExampleTypeMetadata).

## Extending Type Metadata {#extending-type-metadata}

A type can extend another type. The extended type is identified by the URI in
the `extends` property. Consumers MUST retrieve and process
Type Metadata for the extended type before processing the Type Metadata for the extending
type.

The extended type MAY itself extend another type. This can be used to create a
chain or hierarchy of types. The security considerations described in
(#circular-extends) apply in order to avoid problems with circular dependencies.

## Retrieving Type Metadata {#retrieving-type-metadata}

### From a URL in the `vct` Claim {#retrieval-from-vct-claim}

A URI in the `vct` claim can be used to express a type. If the
type is a URL using the HTTPS scheme, Type Metadata can be retrieved from the URL
`https://<authority>/.well-known/vct/<type>`, i.e., by inserting
`/.well-known/vct` after the authority part of the URL.

The Type Metadata is retrieved using the HTTP GET method. The response MUST be a JSON
object as defined in (#type-metadata-format).

If the claim `vct#integrity` is present in the SD-JWT VC, its value
`vct#integrity` MUST be an "integrity metadata" string as defined in Section (#document-integrity).

### From a Registry {#retrieval-from-registry}

A Consumer MAY use a registry to retrieve Type Metadata for a SD-JWT VC type,
e.g., if the type is not a HTTPS URL or if the Consumer does not have
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

### From Type Metadata Glue Documents {#glue-documents}

Credentials MAY encode Type Metadata directly, providing it as "glue
information" to the Consumer.

For JSON-serialized JWS-based credentials, such Type Metadata documents MAY be
included in the unprotected header of the JWS. In this case, the key `vctm` MUST
be used in the unprotected header and its value MUST be an array of
base64url-encoded Type Metadata documents as defined in this specification.
Multiple documents MAY be included for providing a whole chain of types to the
Consumer (see (#extending-type-metadata)).

A Consumer of a credential MAY use the documents in the `vctm`
array instead of retrieving the respective Type Metadata elsewhere as follows:

 * When resolving a `vct` in a credential, the Consumer MUST ensure
   that the `vct` claim in the credential matches the one in the Type Metadata
   document, and it MUST verify the integrity of the Type Metadata document as
   defined in (#document-integrity). The Consumer MUST NOT use the Type Metadata if no hash for integrity protection was provided in `vct#integrity`.
 * When resolving an `extends` property in a Type Metadata document, the Consumer MUST ensure that the value of the `extends` property in the
   Type Metadata document matches that of the `vct` in the Type Metadata document, and it MUST verify the integrity of the Type Metadata document as defined in
   (#document-integrity). The Consumer MUST NOT use the Type Metadata if no hash for integrity protection was provided.

## Extending Type Metadata {#extending-type-metadata}

An SD-JWT VC type can extend another type. The extended type is identified by the URI in
the `extends` property. Consumers MUST retrieve and process
Type Metadata for the extended type before processing the Type Metadata for the extending
type.

The extended type MAY itself extend another type. This can be used to create a
chain or hierarchy of types. The security considerations described in
(#circular-extends) apply in order to avoid problems with circular dependencies.

## Schema Type Metadata {#schema-type-metadata}

### Schema Definition {#schema-definition}

Schemas for Verifiable Credentials are contained in the `schema` or retrieved via the `schema_uri` Type Metadata parameters (as defined in (#type-metadata-format)).
A schema MUST be represented by a JSON Schema document according to draft version 2020-12 [@JSON.SCHEMA.2020-12] or above.

The schema of a Verifiable Credential MUST include all properties that are required by this specification and MUST NOT override their cardinality, JSON data type, or semantic intent.

The following is a non-normative example of a JSON Schema document for the example in (#vc-sd-jwt-example) requiring the presence of the `cnf` claim in an SD-JWT VC presentation:

```
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object",
  "properties":{
    "vct":{
      "type":"string"
    },
    "iss":{
      "type":"string"
    },
    "nbf":{
      "type":"number"
    },
    "exp":{
      "type":"number"
    },
    "cnf":{
      "type":"object"
    },
    "status":{
      "type":"object"
    },
    "given_name":{
      "type":"string"
    },
    "family_name":{
      "type":"string"
    },
    "email":{
      "type":"string"
    },
    "phone_number":{
      "type":"string"
    },
    "address":{
      "type":"object",
      "properties":{
        "street_address":{
          "type":"string"
        },
        "locality":{
          "type":"string"
        },
        "region":{
          "type":"string"
        },
        "country":{
          "type":"string"
        }
      }
    },
    "birthdate":{
      "type":"string"
    },
    "is_over_18":{
      "type":"boolean"
    },
    "is_over_21":{
      "type":"boolean"
    },
    "is_over_65":{
      "type":"boolean"
    }
  },
  "required":[
    "iss",
    "vct",
    "cnf"
  ]
}
```

Note that `iss` and `vct` are always required by this specification.

### Schema Validation {#schema-validation}

If a `schema` or `schema_uri` property is present, a Consumer MUST validate the JSON document resulting from the SD-JWT verification algorithm
(as defined in Section 8 of [@!I-D.ietf-oauth-selective-disclosure-jwt]) against the JSON Schema document provided by the `schema` or `schema_uri` property.

If an `extends` property is present, the schema of the extended type MUST also be validated in the same manner. This process includes
validating all subsequent extended types recursively until a type is encountered that does not contain an `extends` property in its Type Metadata.
Each schema in this chain MUST be evaluated for a specific Verifiable Credential.

If the schema validation fails for any of the types in the chain, the Consumer MUST reject the Verifiable Credential.

The following is a non-normative example of a result JSON document after executing the SD-JWT verification algorithm that is validated against the JSON Schema document in the example provided in (#schema-definition):

```
{
  "vct":"https://credentials.example.com/identity_credential",
  "iss":"https://example.com/issuer",
  "iat":1683000000,
  "exp":1883000000,
  "sub":"6c5c0a49-b589-431d-bae7-219122a9ec2c",
  "address":{
    "country":"DE"
  },
  "cnf":{
    "jwk":{
      "kty":"EC",
      "crv":"P-256",
      "x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
      "y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
    }
  }
}
```

Note, the example above does not contain any `_sd_alg`, `_sd`, or `...` claims.

# Document Integrity {#document-integrity}

Both the `vct` claim in the SD-JWT VC and the various URIs in the Type Metadata MAY be accompanied by a respective claim suffixed with `#integrity`, in particular:

 * `vct` as defined in (#claims),
 * `extends` as defined in (#extending-type-metadata)
 * `uri` as used in two places in (#rendering-metadata)
 * `schema_uri` as defined in (#schema-type-metadata)

The value MUST be an "integrity metadata" string as defined in Section 3 of
[@!W3C.SRI]. A Consumer of the respective documents MUST verify the
integrity of the retrieved document as defined in Section 3.3.5 of [@!W3C.SRI].



# Display Metadata {#display-metadata}

The `display` property is an array containing display information for the type.
The array MUST contain an object for each language that is supported by the
type. The consuming application MUST use the language tag it considers most
appropriate for the user.

The objects in the array MUST have the following properties:

- `lang`: A language tag as defined in Section 2 of [@!RFC5646]. This property is REQUIRED.
- `name`: A human-readable name for the type, intended for end users. This
  property is OPTIONAL.
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
support SVG rendering. The object MUST contain the following properties:

- `logo`: An object containing information about the logo to be displayed for
  the type, as described in (#logo-metadata). This property is OPTIONAL.
- `background_color`: A CSS color value for the background of the credential.
  This property is OPTIONAL.
- `text_color`: A CSS color value for the text of the credential. This property
  is OPTIONAL.

#### Logo Metadata {#logo-metadata}

The `logo` property is an object containing information about the logo to be
displayed for the type. The object contains the following properties:

- `uri`: A URI pointing to the logo image. This property is REQUIRED.
- `uri#integrity`: An "integrity metadata" string as described in
  (#document-integrity). This property is OPTIONAL.
- `alt_text`: A string containing alternative text for the logo image. This
  property is OPTIONAL.

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

# Claim Metadata {#claim-metadata}

The `claims` property is an array of objects containing information about
particular claims for displaying and validating the claims.

The array MAY contain an object for each claim that is supported by the type.
Each object contains the following properties:

- `path`: An array indicating the claim or claims that are being addressed, as
  described below. This property is REQUIRED.
- `display`: An object containing display information for the claim, as
  described in (#claim-display-metadata). This property is OPTIONAL.
- `verification`: A string indicating how the claim was verified, as described in
  (#claim-verification-metadata). This property is OPTIONAL.
- `sd`: A string indicating whether the claim is selectively disclosable, as
  described in (#claim-selective-disclosure-metadata). This property is OPTIONAL.

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

Note: The `path` property MUST point to the respective claim as if all
selectively disclosable claims were disclosed to a Verifier. That means that a
consuming application which does not have access to all disclosures may not be
able to identify the claim which is being addressed.

## Claim Display Metadata {#claim-display-metadata}

The `display` property is an array containing display information for the
claim. The array MUST contain an object for each language that is supported by
the type. The consuming application MUST use the language tag it considers most
appropriate for the user.

The objects in the array MUST have the following properties:

- `lang`: A language tag as defined in Section 2 of [@!RFC5646]. This property is REQUIRED.
- `label`: A human-readable label for the claim, intended for end users. This
  property is OPTIONAL.
- `description`: A human-readable description for the claim, intended for end
  users. This property is OPTIONAL.

## Claim Verification Metadata {#claim-verification-metadata}

The `verification` property is a string indicating how the claim was verified.
The following values are defined:

- `self-attested`: The claim's value was self-attested by the End-User towards
  the Issuer. The Issuer did not verify the claim. For example, in a diploma,
  the residential address of the student may be self-attested.
- `verified`: The claim's value was verified by the Issuer. The Issuer may have
  used a third party to verify the claim. For example, in a diploma, the birth
  date of the student may have been verified by the university using the
  student's passport.
- `authoritative`: The Issuer claims to be the authority to make a statement
  about the claim's value. For example, in a diploma, the degree earned by the
  student may be authoritative if the Issuer is the university that issued the
  degree.

## Claim Selective Disclosure Metadata {#claim-selective-disclosure-metadata}

The `sd` property is a string indicating whether the claim is selectively
disclosable. The following values are defined:

- `always`: The Issuer MUST make the claim selectively disclosable.
- `allowed`: The Issuer MAY make the claim selectively disclosable.
- `never`: The Issuer MUST NOT make the claim selectively disclosable.

If omitted, the default value is `allowed`.

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
credentials, temporary server outages, or denial of service attacks on the
metadata server.

Consumers SHOULD therefore implement a local cache as described in
(#retrieval-from-local-cache) if possible. Such a cache MAY be populated with metadata before
the credential is used.

Issuers MAY provide glue documents as described in (#glue-documents) to provide
metadata directly with the credential and avoid the need for network requests.

These measures allow the Consumers to continue to function even if
the metadata server is temporarily unavailable and avoid privacy issues as
described in (#privacy-preserving-retrieval-of-type-metadata).

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

This specification defines validation and processing rules for verifiable credentials using JSON
payloads and secured by SD-JWT [@!I-D.ietf-oauth-selective-disclosure-jwt]. Other specifications exist
that define their own verifiable credential formats; for example, W3C Verifiable
Credential Data Model (VCDM) 2.0 [@W3C.VCDM] defines a data model for verifiable credentials encoded as JSON-LD, and
ISO/IEC 18013-5:2021 [@ISO.18013-5] defines a representation of verifiable credentials in the mobile document (mdoc)
format encoded as CBOR and secured using COSE.

## Privacy-Preserving Retrieval of Type Metadata {#privacy-preserving-retrieval-of-type-metadata}

In (#retrieving-type-metadata), various methods for distributing and retrieving
Type Metadata are described. For methods which rely on a network connection to a
URL (e.g., provided by an Issuer), third parties (like the Issuer) may be able
to track the usage of a credential by observing requests to the Type Metadata URL.

Consumers SHOULD prefer methods for retrieving Type Metadata that do not
leak information about the usage of a credential to third parties. The
recommendations in (#robust-retrieval) apply.

<reference anchor="IANA.well-known" target="http://www.iana.org/assignments/well-known-uris">
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

<reference anchor="JSON.SCHEMA.2020-12" target="https://json-schema.org/draft/2020-12/release-notes">
  <front>
    <author fullname="OpenJS Foundation"></author>
    <title>JSON Schema (2020-12)</title>
  </front>
</reference>
{backmatter}

# IANA Considerations

## JSON Web Token Claims Registration

- Claim Name: "vct"
- Claim Description: Verifiable credential type identifier
- Change Controller: IETF
- Specification Document(s): [[ (#type-claim) of this of this specification ]]

- Claim Name: "vct#integrity"
- Claim Description: SD-JWT VC vct claim "integrity metadata" value
- Change Controller: IETF
- Specification Document(s): [[ (#document-integrity) of this of this specification ]]

## Media Types Registry

### application/vc+sd-jwt {#application-vc-sd-jwt}

The Internet media type for a SD-JWT VC is `application/vc+sd-jwt`.

* Type name: `application`
* Subtype name: `vc+sd-jwt`
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
* Specification document: [[ (#jwt-vc-issuer-metadata) of this of this specification ]]
* Related information: (none)

# Examples

Important: The following examples are not normative and provided for
illustrative purposes only. In particular, neither the structure of the claims
nor the selection of selectively disclosable claims are normative.

Line breaks have been added for readability.

## Example 1: Person Identification Data (PID) Credential

This example shows how the artifacts defined in this specification could
be used to represent the concept of a Person Identification Data (PID)
[@EUDIW.ARF] using the data of a German citizen.

Key Binding is applied
using the Holder's public key passed in a `cnf` claim in the SD-JWT.

The Issuer is using the following input claims set:

<{{examples/03-pid/user_claims.json}}

The following is the issued SD-JWT:

<{{examples/03-pid/sd_jwt_issuance.txt}}

The following payload is used for the SD-JWT:

<{{examples/03-pid/sd_jwt_payload.json}}

The following Disclosures are created by the Issuer:

{{examples/03-pid/disclosures.md}}

The following shows a presentation of the SD-JWT with a Key Binding JWT that discloses only nationality and the fact that the person is over 18 years old:

<{{examples/03-pid/sd_jwt_presentation.txt}}

The following is the payload of a corresponding Key Binding JWT:

<{{examples/03-pid/kb_jwt_payload.json}}

After the validation, the Verifier will have the following data for further processing:

<{{examples/03-pid/verified_contents.json}}

## Example 2: Type Metadata {#ExampleTypeMetadata}

```json
{
  "vct": "https://betelgeuse.example.com/education_credential",
  "name": "Betelgeuse Education Credential - Preliminary Version",
  "description": "This is our development version of the education credential. Don't panic.",
  "extends": "https://galaxy.example.com/galactic-education-credential-0.9",
  "extends#integrity": "sha256-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-WRL5",
  "display": [
    {
      "lang": "en-US",
      "name": "Betelgeuse Education Credential",
      "description": "An education credential for all carbon-based life forms on Betelgeusians",
      "rendering": {
        "simple": {
          "logo": {
            "uri": "https://betelgeuse.example.com/public/education-logo.png",
            "uri#integrity": "sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V",
            "alt_text": "Betelgeuse Ministry of Education logo"
          },
          "background_color": "#12107c",
          "text_color": "#FFFFFF"
        },
        "svg_templates": [
          {
            "uri": "https://betelgeuse.example.com/public/credential-english.svg",
            "uri#integrity": "sha256-8cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-9c",
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
      "lang": "de-DE",
      "name": "Betelgeuse-Bildungsnachweis",
      "rendering": {
        "simple": {
          "logo": {
            "uri": "https://betelgeuse.example.com/public/education-logo-de.png",
            "uri#integrity": "sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V",
            "alt_text": "Logo des Betelgeusischen Bildungsministeriums"
          },
          "background_color": "#12107c",
          "text_color": "#FFFFFF"
        },
        "svg_templates": [
          {
            "uri": "https://betelgeuse.example.com/public/credential-german.svg",
            "uri#integrity": "sha256-8cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-9c",
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
      "path": [
        "name"
      ],
      "display": [
        {
          "lang": "de-DE",
          "label": "Vor- und Nachname",
          "description": "Der Name des Studenten"
        },
        {
          "lang": "en-US",
          "label": "Name",
          "description": "The name of the student"
        }
      ],
      "verification": "verified",
      "sd": "allowed"
    },
    {
      "path": [
        "address"
      ],
      "display": [
        {
          "lang": "de-DE",
          "label": "Adresse",
          "description": "Adresse zum Zeitpunkt des Abschlusses"
        },
        {
          "lang": "en-US",
          "label": "Address",
          "description": "Address at the time of graduation"
        }
      ],
      "verification": "self-attested",
      "sd": "always"
    },
    {
      "path": [
        "address",
        "street_address"
      ],
      "display": [
        {
          "lang": "de-DE",
          "label": "Straße"
        },
        {
          "lang": "en-US",
          "label": "Street Address"
        }
      ],
      "verification": "self-attested",
      "sd": "always"
    },
    {
      "path": [
        "degrees",
        null
      ],
      "display": [
        {
          "lang": "de-DE",
          "label": "Abschluss",
          "description": "Der Abschluss des Studenten"
        },
        {
          "lang": "en-US",
          "label": "Degree",
          "description": "Degree earned by the student"
        }
      ],
      "verification": "authoritative",
      "sd": "allowed"
    }
  ],
  "schema_url": "https://exampleuniversity.com/public/credential-schema-0.9",
  "schema_url#integrity": "sha256-o984vn819a48ui1llkwPmKjZ5t0WRL5ca_xGgX3c1VLmXfh"
}
```

# Acknowledgements {#Acknowledgements}

We would like to thank
Alen Horvat,
Andres Uribe,
Christian Bormann,
Giuseppe De Marco,
Lukas J Han,
Michael Jones,
Mike Prorock,
Orie Steele,
Paul Bastian,
Torsten Lodderstedt,
Tobias Looker, and
Kristina Yasuda
for their contributions (some of which substantial) to this draft and to the initial set of implementations.

# Document History

-05

* Include display and claim type metadata
* Added example for type metadata

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

