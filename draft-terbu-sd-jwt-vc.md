%%%
title = "Verifiable Credentials based on SD-JWT with JSON payloads"
abbrev = "vc-sd-jwt"
ipr = "none"
workgroup = "TBD"
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

This specification describes data formats, validation and processing rules to
express Verifiable Credentials based on the securing mechanisms of SD-JWT
(TBD: see oauth-selective-disclosure-jwt) and JSON payloads.

{mainmatter}

# Introduction

A Verifiable Credential is an tamper-evident statement made by an Issuer about
a Subject of the Verifiable Credential. Verifiable Credentials are issued to
Holders which can present Verifiable Credentials to Verifiers typically in form
of Verifiable Presentations.

These relationships are described by the three-party-model which involves the
following parties:

1. Issuer: The entity that issues the Verifiable Credential to the Holder, who
is tthe person or entity being issued the credential.
1. Verifier: The entity that verifies the Verifiable Credential presented by
the Subject, for example to prove eligibility to access certain services.
1. Holder: The person or entity being issued the Verifiable Credential, who
 may present the Verifiable Credential to a Verifier for verification.

Verifiers have to trust Issuers to make
trustworthy statements about the Subject and they can additionally require that
the Holder provides a proof that they are the intended Holder of the Verifiable
Credential which can important for security reasons. This is only possible if
an Issuer binds the Verifiable Credential to a specific Holder at the time of
issuance.

Signed JSON Web Tokens (JWTs) [@!RFC7519] can in principle be used to express
Verifiable Credentials in a way that is easy to understand and process as it
builds upon established web primitives. However, JWTs do not support selective
disclosure, i.e., the ability to disclose only a subset of the claims contained
in the JWT. This is a common problem in the so-called three-party model: An
Issuer creates a Verifiable Credential for some End-User (Holder), who then
presents this credential to multiple Verifiers. A credential might contain a
large number of claims, but the Holder typically only wants to disclose a subset
of these claims to a Verifier. In this case, the Holder would have to receive a
new signed JWT from the Issuer, containing only the claims that should be
disclosed, for each interaction with a new Verifier. This is inefficient,
costly, and the necessary interaction with the Issuer introduces additional
privacy risks.

SD-JWT is a specification that introduces conventions to support selective
disclosure for JWTs: For an SD-JWT document, a Holder can decide which claims to
release (within bounds defined by the Issuer). This format is therefore
perfectly suitable for Verifiable Credentials.

SD-JWT itself does not define the claims that must be used within the payload of
the token or their semantics. This specification therefore defines how
Verifiable Credentials can be expressed using SD-JWT.

JWTs are used to protect the integrity of JSON payloads, which
can contain claims that are registered in the IANA JWT Claim Registry, as well
as public and private claims. Private claims are not relevant for this
specification due to the openness of the three-party-model. Since SD-JWTs are
based on JWTs, this specification aims to express the basic Verifiable Credential
data model purely through JSON payloads, using registered claims while allowing
Issuers to use additional registered claims, as well as new or existing public
claims, to make statements about the Subject of the Verifiable Credential.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119 [@!RFC2119].

## Terms and Definitions

Verifiable Credential:
: TBD

Credential:
: TBD

Verifiable Presentation:
: TBD

Issuer:
: An entity that issues a Verifiable Credential.

Holder:
: An entity that receives Verifiable Credentials from the Issuer and has
control over them. Holders present Verifiable Credentials as Verifiable
Presentations to Verifiers and can prove control over them.

Verifier:
: An entity that requests, validates and processes Verifiable Credentials and
Verifiable Presenations.

Verifiable Credential based on SD-JWT (VC-SD-JWT):
: Refers to SD-JWT Combined Format for Issuance [see TBD] that complies with
this specification. In the three-party-model, this representation is used for
the Verifiable Credential and is transferred from the Issuer to the Holder.

Verifiable Presentation based on SD-JWT (VP-SD-JWT):
: Refers to SD-JWT Combined Format for Presentation [see TBD] that complies
with this specification. In the three-party-model, this representation is used
for the Verifiable Presentation and is transferred from the Issuer to the
Holder.

Credential based on SD-JWT (C-SD-JWT):
: Refers to the original unsecured JSON payload of the VC-SD-JWT.

# Scope

TBD

# Use Cases

TBD: explain use cases of the three-party-model.

TBD: conventional crypt, hardware security, hsm, mobile secure area,
compliance with FIPS

# Overview

* This specification defines
  - Data model and media types for Verifiable Credentials and Presentations based on SD-JWTs.
  - Validation and processing rules for Verifiers
  - Mapping mechanisms to related other data models
  - ...

# Verifiable Credentials

This specification defines the media type `vc+sd-jwt` which describes a
VC-SD-JWT with the following components:

1. An SD-JWT to protect the integrity of the claims, to enable selective disclosure and to ensure authorship of the VC-SD-JWT. The SD-JWT header parameters and the payload is further defined by this specification.
1. The full set of SD-JWT Disclosures that contain the claims in plain text.

## Data Format

### Header Parameters

The `typ` header parameter of the SD-JWT MUST be present. The `typ` value MUST
use `vc+sd-jwt`. This indicates that the payload of the SD-JWT contains plain
JSON and follows the rules as defined in this specification. It further
indicates that the SD-JWT is a SD-JWT component of a VC-SD-JWT.

The following is a non-normative example of a decoded SD-JWT header:

```
{
  "alg": "ES256",
  "typ": "vc+sd-jwt"
}
```

### Payload

VC-SD-JWTs and VP-SD-JWTs can use any
claim registered in the "JSON Web Token Claims" registry as defined in
[@!RFC7519].

Some of the claims in a VC MUST NOT be selectively disclosed as they are
always required for processing on the verifier side. All other claims can be
made selectively disclosable by the issuer when issuing the respective
VC-SD-JWT.

VC-SD-JWTs and VP-SD-JWTs MAY contain additional
registered or public claims depending on the application.

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

#### Usage of registered JWT Claims

The following are non-selectively disclosable registered JWT claims that
SD-JWTs of VC-SD-JWTs contain for specific purposes:

* `iss`
    * REQUIRED. The issuer of the Verifiable Credential. The value of `iss`
MUST be a URI. See [@!RFC7519] for more information.
* `iat`
    * REQUIRED. The time of issuance of the Verifiable Credential. See [@!RFC7519]
for more information.
* `nbf`
    * REQUIRED. The time before which the Verifiable Credential MUST NOT be
accepted before validating. See [@!RFC7519] for more information.
* `exp`
    * REQUIRED. The expiry time of the Verifiable Credential after which the
proof of the Verifiable Credential is no longer valid. See [@!RFC7519] for more
information.
* `cnf`
    * OPTIONAL. The confirmation method can be used to verify the holder
binding of the Verifiable Presentation. See [@!RFC7800] for more information.
* `type`
    * REQUIRED. The type of the Verifiable Credential, e.g.,
`IdentityCredential`. The claims belonging to the type can be contained in
different components of the VC-SD-JWT, e.g., SD-JWT or Disclosures.
* `status`
    * OPTIONAL. The information on how to read the status of the Verifiable
Credential. See TBD for more information.

The following are selectively disclosable registered JWT claims that
SD-JWTs of VC-SD-JWTs contain for specific purposes:

* `sub`
    * OPTIONAL. The identifier of the Subject of the Verifiable Credential.
The value of `sub` MUST be a URI. The Issuer MAY use it to provide the Subject
identifier assigned and maintained by the Issuer. There is no requirement for
a binding to exist between `sub` and `cnf` claims.

## Example

The following is a non-normative example of a Credential acting as the input
for the VC-SD-JWT:

```
{
   "iss":"https://example.com",
   "nbf":1541493724,
   "iat":1541493724,
   "cnf":{
      "jwk":{
         "kty":"RSA",
         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbf
           AAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst
           n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F
           DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9
           1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHa
           Q-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw”,
         "e":"AQAB"
      }
   },
   "type":"IdentityCredential",
   "given_name":"John",
   "family_name":"Doe",
   "email":"johndoe@example.com",
   "phone_number":"+1-202-555-0101",
   "address":{
      "street_address":"123 Main St",
      "locality":"Anytown",
      "region":"Anystate",
      "country":"US"
   },
   "birthdate":"1940-01-01",
   "is_over_18":true,
   "is_over_21":true,
   "is_over_65":true
}
```

The following is a non-normative example of how the Credential above can be
used in a SD-JWT where the resulting VC-SD-JWT contains only claims about
the Subject that are selectively disclosable:

```
{
   "iss":"https://example.com",
   "iat":1541493724,
   "exp":1735689661,
   "nbf":1541493724,
   "cnf":{
      "jwk":{
         "kty":"RSA",
         "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbf
           AAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst
           n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F
           DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9
           1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHa
           Q-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB"
      }
   },
   "type":"IdentityCredential",
   "_sd":[
      "2cj0qo1YI8aGLOPCEzIr0mexil6_9tVz5KnIpY3fszs",
      "H033gGqGyBCT7VmtYky-1gqqTg9JT8kg9WFJTTN1iVY",
      "RKE58nhM1GLxUmfvPaZhxNEq8kNplQYnOZlLJosLomY",
      "S7ebWHiOEgQDLG6JcpYkuMKMCb40uxFUSUimK94MuDc",
      "WkP5oQu7qxPAxLVPKcFuP4rD5TC0T4CekiYi333zQP4",
      "f4nimkh9dcwJ8JK46zlad_zgyYJfZFPImAWBNh86Kb0",
      "goqT4HD2DOmnPF1wNMLNiYuj4SgYtKjfQQHO--CSh0o",
      "lheBqvJLJPRLsoXVF68rmkn9jL73iGCF0V5sJjPlt68",
      "tAQ3Er6qd3UwQLrZYRe3fMF4J6MXdz5tJMJfJw48I0g"
   ],
   "_sd_alg":"sha-256"
}
```

The following are Disclosures of the non-normative example from above:

*Disclosure for given_name:*

- SHA-256 Hash: `f4nimkh9dcwJ8JK46zlad_zgyYJfZFPImAWBNh86Kb0`
- Disclosure: `WyJuWUpCd1Q0OERQTEtYcVd1UmJ4NVNRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`
- Contents:

```
["nYJBwT48DPLKXqWuRbx5SQ", "given_name", "John"]
```

TBD: add other disclosures.

## Validation Rules and Processing

A Verifier MUST validate an VC-SD-JWT as follows:

 1. REQUIRED. Verify the SD-JWT as defined in Section 6.2 of (TBD: see
oauth-selective-disclosure-jwt). For the verification, the `iss` claim in the
SD-JWT MAY be used to retrieve the public key from the JWT Issuer Metadata
configuration (as defined in {#jwt-issuer-metadata}) of the VC-SD-JWT issuer.
A verifier MAY use alternative methods to obtain the public key to verify the
signature of the SD-JWT.
 1. OPTIONAL. If `status` is present in the verified payload of the SD-JWT,
the status SHOULD be checked. It depends on the Verifier policy to reject or
accept an VP-SD-JWT based on the status of the Verifiable Credential.

Additional validation rules MAY apply, but their use is out of the scope of
this specification.

### JWT Issuer Metadata {#jwt-issuer-metadata}

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

The JWT Issuer Metadata configuration MUST be a JSON document compliant with
this specification and MUST be returned using the `application/json` content
type.

This specification defines the following JWT Issuer Metadata parameters:

* `jwks_uri`
    * OPTIONAL. URL string referencing the JWT Issuer's JSON Web Key (JWK) Set
[@RFC7517] document which contains the JWT Issuer's public keys. The value of
this field MUST point to a valid JWK Set document. Use of this parameter is
RECOMMENDED, as it allows for easy key rotation.
* `jwks`
    * OPTIONAL. JWT Issuer's JSON Web Key Set [RFC7517] document value, which
contains the JWT Issuer's public keys. The value of this field MUST be a JSON
object containing a valid JWK Set. This parameter is intended to be used by JWT
Issuer that cannot use the `jwks_uri` parameter.

JWT Issuer Metadata MUST include either `jwks_uri` or `jwks` in their JWT
Issuer Metadata, but not both.

It is RECOMMENDED that the JWT contains a `kid` JWT header parameter that can
be used to lookup the public key in the JWK Set included by value or referenced
in the JWT Issuer Metadata.

The following is a non-normative example of a JWT Issuer Metadata including
`jwks`:

```
{
   "jwks":{
      "keys":[
         {
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

The following is a non-normative example of a JWT Issuer Metadata including
`jwks_uri`:

```
{
   "jwks_uri":"https://jwt-issuer.example.org/my_public_keys.jwks"
}
```

# Verifiable Presentations

This specification defines the media type `vp+sd-jwt` which describes the VP-SD-JWT with the following components:

 1. The SD-JWT from the VC-SD-JWT.
 1. A subset of the SD-JWT Disclosures that are selectively disclosed by the Holder.
 1. An optional holder binding JWT that proves the Holder is the intended Holder of the Verifiable Credential. Note, it is the responsibility for the Issuer to include a confirmation method in the Verifiable Credential. This process is referred to as holder binding. This enables the Holder to prove they are the intended Holder of the Verifiable Credential. Further note, it is up to the Verifier to require or to not require the Holder to prove posessions of the confirmation method.

## Examples

The following is a non-normative example of a VP-SD-JWT without holder binding:

```
TBD
```

The following is a non-normative example of a VP-SD-JWT with holder binding:

```
TBD
```

## Validation Rules and Processing

TBD: same as VC-SD-JWT (-> refer to SD-JWT) + Holder Binding

# Security Considerations

TBD

# Privacy Considerations

TBD

# Relationships to Other Documents

## W3C Verifiable Credential Data Model 2.0

The W3C VCDM 2.0 (see TBD) defines a JSON-LD vocabulary for Verifiable
Credentials and Verifiable Presentations. To interop with the W3C VCDM 2.0 data
model defined in [TBD], this specification defines mapping algorithm for
VC-SD-JWT and VP-SD-JWT to the vocabulary and data model defined W3C VCDM 2.0
which is based on JSON-LD.

### VC Directory

This specification registers the media types `application/vp+sd-jwt` and
`application/vc+sd-jwt` in the W3C Verifiable Credentials (VC) Directory.

### Mapping Algorithm

The following is a uni-directional transformation algorithm that takes in a
VC-SD-JWT conformant to this specification and maps it
to the corresponding properties in the W3C VCDM 2.0
which is based on a JSON-LD vocabulary. It includes specific handling for JWT
claims used in this specification. The function returns a Verifiable
Credential object in the W3C VCDM 2.0 format.

```
function get_credential_from_vc_sd_jwt(vc_sd_jwt):
  // TBD
  return credential

function map_vc_sd_jwt_to_w3c(vc_sd_jwt):

  // construct input credential (JSON object)
  credential = get_credential_from_vc_sd_jwt(vc_sd_jwt)

  return map_to_w3c(credential)

  vc = {
    "@context": [
      "https://www.w3.org/ns/credentials/v2"
    ]
  }
  vc.issuedAt = epochTimeToISO(credential.iat)
  vc.validFrom = epochTimeToISO(credential.nbf)
  vc.validUntil = epochTimeToISO(credential.exp)
  vc.id = credential.jti
  vc.issuer = credential.iss
  vc.type = credential.type

  // remove all handled claims
  credential = drop_claims(credential, ...)

  // add all remaining claims to credentialSubject
  // ignore other claims such as cnf where no corresponding
  // representation exists
  vc.credentialSubject = {
    "id": credential.sub,
    ... credential
  }

  return vc
```

The following is a uni-directional transformation algorithm from a VP-SD-JWT onto W3C Verifiable Presentations
in pseudo-code:

```
function map_vc_sd_jwt_to_w3c(vc_sd_jwt):
  TBD: similar to above but using W3C VP + VC

```

####

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

# IANA Considerations

## JSON Web Token Claims Registration

 Claim Name: "type"
   o  Claim Description: Credential Type
   o  Change Controller: IESG
   o  Specification Document(s): Section XXX of this document

## Media Types Registry

TBD

### application/vc+sd-jwt

The Internet media type for a VC-SD-JWT is `application/vc+sd-jwt`.

Type name: : `application`

Subtype name: : `vc+sd-jwt`

Required parameters: : n/a

Optional parameters: : n/a

Encoding considerations: : 8-bit code points; VC-SD-JWT values are encoded as a
series of base64url-encoded values (some of which may be the empty string)
separated by period ('.') and tilde ('~') characters.

Security considerations: : See Security Considerations in Section TODO.

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
  - Author: Oliver Terbu <TODO@email.com>
  - Change controller: IETF

### application/vp+sd-jwt

The Internet media type for a VC-SD-JWT is `application/vp+sd-jwt`.

Type name: : `application`

Subtype name: : `vp+sd-jwt`

Required parameters: : n/a

Optional parameters: : n/a

Encoding considerations: : 8-bit code points; VP-SD-JWT values are encoded as a
series of base64url-encoded values (some of which may be the empty string)
separated by period ('.') and tilde ('~') characters.

Security considerations: : See Security Considerations in Section TODO.

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
  - Author: Oliver Terbu <TODO@email.com>
  - Change controller: IETF

# Acknowledgements {#Acknowledgements}

TBD

# Document History

-00

* Initial Version
