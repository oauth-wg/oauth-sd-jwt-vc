%%%
title = "SD-JWT-based Verifiable Credentials with JSON payloads"
abbrev = "sd-jwt-vc"
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

This document specifies Verifiable Credentials based on Selective Disclosure JSON Web Tokens (SD-JWT) with JSON payloads.

{mainmatter}

# Introduction


TBD: why?
- simplicity
- JWTs are well-known, popular but doesn't work best with three-party-model
- Also no selective disclosure, which impacts costs and security.

This specification describes data formats, validation and processing rules for SD-JWT expresing Verifiable Credentials.

## Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119 [@!RFC2119].

## Terms and Definitions

TBD

## Abbreviations

TBD

# Scope

TBD

# Use Cases

TBD: explain three-party-model and use cases

TBD: conventional crypt, hardware security, hsm, mobile secure area, compliance with FIPS

# Overview

TBD

# Data Format

TBD

## Header Parameters

The `typ` header parameter of the SD-JWT-VC MUST be present. The `typ` value MUST use the media type `vc+sd-jwt`that is registered by this specification. This indicates that the payload of the SD-JWT-VC contains plain JSON and follows the rules as defined in this specification.

The following is a non-normative example of a decoded SD-JWT-VC header:

```
{
  "alg": "ES256",
  "typ": "vc+sd-jwt"
}
```

## Payload

SD-JWT-VCs as defined in this specification can use any claim registered in the “JSON Web Token Claims” registry as defined in RFC 7519.

Some of the claims in a VC MUST NOT be selectively disclosed as they are always required for processing on the verifier side. All other claims can be made selectively disclosable by the issuer when issuing the respective SD-JWT-VC.

SD-JWT-VCs MAY contain additional claims depending on the application.

### `status` claim {#status-claim}

TBD: might get removed once other draft spec finished

### `type` claim {#type-claim}

TBD

### Usage of registered JWT Claims

The following are non-selectively disclosable registered JWT claims that SD-JWT-VCs contain for specific purposes:

* `iss`
    * REQUIRED. The issuer of the Verifiable Credential. The value of `iss` MUST be a URI. See [JWT] for more information.
* `iat`
    * REQUIRED. The time of issuance of the Verifiable Credential.
* `exp`
    * REQUIRED. The expiry time of the Verifiable Credential after which the proof of the Verifiable Credential is no longer valid.
* `cnf`
    * OPTIONAL. The confirmation method can be used to verify the Holder Binding JWT of the disclosed SD-JWT.
* `type`
    * REQUIRED. The type or types of the Verifiable Credential. In the general case, the `type` value is an array of case-sensitive strings, each containing a `StringOrURI` value. In the special case when the SD-JWT has one credential type, the `type` value MAY be a single case-sensitive string containing a `StringOrURI` value.
* `status`
    * OPTIONAL. The information on how to read the status of the Verifiable Credential.
* `nbf`
    * OPTIONAL. The time before which the SD-JWT-VC MUST NOT be accepted before validating.

The following are selectively disclosable registered JWT claims that SD-JWT-VCs contain for specific purposes:

* `sub`
    * OPTIONAL. The identifier of the subject of the Verifiable Credential. The value of `sub` MUST be a URI..

# Validation Rules and Processing

A verifier MUST validate an SD-JWT-VC as follows:

* REQUIRED. Verify the SD-JWT-VC as per SD-JWT.
* REQUIRED. Perform Issuer Authentication as described in {#issuer-authentication}.
* OPTIONAL. If `status` is present in the SD-JWT-VC, the status of the SD-JWT-VC SHOULD be checked. It depends on the verifier policy to reject or accept an SD-JWT-VC based on the status of the Verifiable Credential.

Additional validation rules MAY apply but their use is out-of-scope of this specification.

## Issuer Authentication {#issuer-authentication}

Verifiers processing SD-JWT-VCs MUST verify the signature of the SD-JWT with the public key of the SD-JWT-VC issuer. This makes sure that the SD-JWT-VC was issued by the SD-JWT-VC issuer and that it has not been tampered with since issuance.

The `iss` claim in the SD-JWT-VC MAY be used to retrieve the public key from the JWT Issuer Metadata configuration (as defined in {#jwt-issuer-metadata}) of the SD-JWT-VC issuer. A verifier MAY use alternative methods to obtain the public key to verify the signature of the SD-JWT.

## JWT Issuer Metadata {#jwt-issuer-metadata}

This specification defines the JWT Issuer Metadata to retrieve the JWT Issuer Metadata configuration of the JWT Issuer of the JWT. The JWT Issuer is identified by the `iss` claim in the JWT. Use of the JWT Issuer Metadata is OPTIONAL.

JWT Issuers publishing JWT Issuer Metadata MUST make a JWT Issuer Metadata configuration available at the path formed by concatenating the string `/.well-known/jwt-issuer` to the `iss` claim value in the JWT. The `iss` MUST be a case-sensitive URL using the HTTPS scheme that contains scheme, host and, optionally, port number and path components, but no query or fragment components.

The JWT Issuer Metadata configuration MUST be a JSON document compliant with this specification and MUST be returned using the application/json content type.

This specification defines the following JWT Issuer Metadata parameters:

* `jwks_uri`
    * OPTIONAL. URL string referencing the JWT Issuer’s JSON Web Key (JWK) Set [RFC7517] document, which contains the JWT Issuer's public keys. The value of this field MUST point to a valid JWK Set document. Use of this parameter is preferred over the `jwks` parameter, as it allows for easier key rotation. JWT Issuer MUST include either `jwks_uri` or `jwks` in their JWT Issuer Metadata. `jwks_uri` and `jwks` MUST NOT both be present in the same JWT Issuer Metadata.
* `jwks`
    * OPTIONAL. JWT Issuer’s JSON Web Key Set [RFC7517] document value, which contains the JWT Issuer’s public keys. The value of this field MUST be a JSON object containing a valid JWK Set. This parameter is intended to be used by JWT Issuer that cannot use the `jwks_uri` parameter. JWT Issuer MUST include either `jwks_uri` or `jwks` in their JWT Issuer Metadata. `jwks_uri` and `jwks` MUST NOT both be present in the same JWT Issuer Metadata.

It is RECOMMENDED that the JWT contains a `kid` JWT header parameter that can be used to lookup the public key in the JWK Set included by value or referenced in the JWT Issuer Metadata.

The following is a non-normative example of a JWT Issuer Metadata including `jwks`:

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

The following is a non-normative example of a JWT Issuer Metadata including `jwks_uri`:

```
{
   "jwks_uri":"https://jwt-issuer.example.org/my_public_keys.jwks"
}
```

# Verifiable Presentation Support

TBD: we would like to register a media type for vp+sd-jwt

# Security Considerations

TBD

# Privacy Considerations

TBD

# Relationships to Other Documents

## W3C Verifiable Credential Data Model 2.0

### Mapping Mechanism

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

# IANA Considerations

TBD

# Acknowledgements {#Acknowledgements}

TBD

# Notices

TBD

# Document History

TBD
