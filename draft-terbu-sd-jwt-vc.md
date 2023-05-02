---
title: "Securing Verifiable Credentials and Presentations using SD-JWTs"
category: info

docname: draft-terbu-sd-jwt-vc-latest
submissiontype: independent  # also: "IETF", "IAB", or "IRTF"
number:
date:
v: 3
venue:
  github: "awoie/draft-terbu-sd-jwt-vc"
  latest: "https://awoie.github.io/draft-terbu-sd-jwt-vc/draft-terbu-sd-jwt-vc.html"

author:
 -
    fullname: Oliver Terbu
    organization: SpruceID
    email: oliver.terbu@spruceid.com


normative:

informative:


--- abstract

Selective Disclosure for JWTs (SD-JWT) [TBD] is a xyz. Providing a mechanism of how to secure W3C Verifiable Credentials Data Model [TBD] with SD-JWT allows xyz. A SD-JWT encodes a set of claims as xyz. …

This specification describes how to secure media types expressing Verifiable Credentials and Verifiable Presentations as described in [VC-DATA-MODEL] using SD-JWTs [TBD].

--- middle

# Introduction

Selective Disclosure for JWTs (SD-JWT) [TBD] is a xyz. Providing a representation of the W3C Verifiable Credentials Data Model [TBD] for SD-JWT allows xyz. A SD-JWT encodes a set of claims as xyz. ...

This specification describes two media types representing the following: 
- SD-JWT Verifiable Credential (SD-JWT-VC): A Verifiable Credential secured with a Selective Disclosure JWT (SD-JWT)
- SD-JWT Verifiable Presentation (SD-JWT-VP): A Verifiable Presentation secured with a Selective Disclosure JWT (SD-JWT).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Securing Verifiable Credentials

This specification defines a media type for Verifiable Credentials secured with SD-JWTs (SD-JWT-VC) and the SD-JWT-VC header parameters and JWT claims used in the payload of SD-JWT-VCs.

Verifiable Credentials secured using this specification contain JSON objects. A uni-directional mapping mechanism on the W3C JSON-LD vocabulary is defined in Appendix B [TBD].

## Header Parameters

The "typ" header parameter of the SD-JWT-VC MUST be present. The “typ” value MUST use the media type "vc+sd-jwt" that is registered by this specification. This indicates that the payload of the SD-JWT-VC contains plain JSON.

The following is a non-normative example of a decoded SD-JWT-VC header:

~~~
{
  "alg": "ES256",
  "typ": "vc+sd-jwt"
}
~~~

## Usage of registered JWT Claims

This section describes non-selectively disclosable registered JWT claims that SD-JWT-VCs contain for specific purposes. SD-JWT-VCs MAY contain additional claims depending on the application.

"iss"
REQUIRED. The issuer of the Verifiable Credentials. The value of “iss” MUST be a URI. See [JWT] for more information.

"sub"
OPTIONAL. The identifier of the subject of the Verifiable Credential. The value of “sub” MUST be a URI.

"iat"
REQUIRED. The time of issuance of the Verifiable Credential. 

"nbf"
OPTIONAL. The time before which the SD-JWT-VC MUST NOT be accepted before validating.

"exp"
OPTIONAL. The expiry time of the Verifiable Credential after which the proof of the Verifiable Credential is no longer valid.

"cnf"
OPTIONAL. The confirmation method can be used to verify the Holder Binding JWT of the disclosed SD-JWT.

"type"
REQUIRED. The type or types of the Verifiable Credential. In the general case, the "type" value is an array of case-sensitive strings, each containing a StringOrURI value. In the special case when the SD-JWT has one credential type, the "type" value MAY be a single case-sensitive string containing a StringOrURI value. 

"status"
OPTIONAL. The information on how to read the status of the Verifiable Credential.

### "status" claim

The "status" claim contains information on how the status of the Verifiable Credential can be obtained using the mechanism described in [CWT/JWT-based Status List]. The status claim is a JSON Object with the following members:

"index"
REQUIRED. TBD

"url"
REQUIRED. TBD

"purpose"
REQUIRED. TBD. The "purpose" member identifies the purpose of the status of the Verifiable Credential. Its value is an array of purpose values. Values defined by this specification are:
- "revocation" (see [CWT/JWT-based Status List])
- "suspension" (see [CWT/JWT-based Status List])

## Issuer Authentication

Verifiers processing Verifiable Credentials typically have to authenticate the issuer of the Verifiable Credential during the verification process. The process of discovering the public key to verify the signature of the SD-JWT-VC is typically based on the value of the "iss" claim but can use different approaches.

### JWT Issuer Metadata Discovery

This specification defines the JWT Issuer Metadata Discovery protocol to discover the authoritative public key for the SD-JWT-VC issuer based on a HTTPS URL of the "iss" claim. Use of the JWT Issuer Metadata Discovery protocol is OPTIONAL.

SD-JWT-VC issuers publishing JWT metadata MUST make a JSON document available at the path formed by concatenating the string /.well-known/jwt-issuer to the "iss" claim in the SD-JWT-VC. The "iss" MUST be a HTTPS URL. If the Credential Issuer value contains a path component, any terminating / MUST be removed before appending /.well-known/jwt-issuer.

This specification defines the following JWT Issuer Metadata:
- "jwks": REQUIRED. The authoritative public keys of the JWT issuer as a JWKS. It is RECOMMENDED that the SD-JWT-VC contains a "kid" JWT header parameter that can be used to lookup the public key in the "jwks" value.

## Examples

The following is an example of an SD-JWT that secures a Verifiable Credential.

Below is a non-normative example of an SD-JWT-VC.

The following data will be used in this example:

~~~
{
   "iss":"https://example.com",
   "jti":"http://example.com/credentials/3732",
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
~~~

The payload of a corresponding SD-JWT-VC looks as follows:

~~~
{
   "iss":"https://example.com",
   "iat":1541493724,
   "exp":1735689661,
   "jti":"http://example.com/credentials/3732",
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
~~~

Disclosures:

*Disclosure for given_name:*

SHA-256 Hash: f4nimkh9dcwJ8JK46zlad_zgyYJfZFPImAWBNh86Kb0

Disclosure:

~~~
WyJuWUpCd1Q0OERQTEtYcVd1UmJ4NVNRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd
~~~

Contents:

~~~
["nYJBwT48DPLKXqWuRbx5SQ", "given_name", "John"]
~~~

TBD: complete examples above and fix hashes

# Securing Verifiable Presentations

This specification defines a media type for Verifiable Presentations secured with SD-JWTs (SD-JWT-VP). A file containing this media type MUST contain a SD-JWT Disclosure using the Combined Format for Presentation as per [SD-JWTs].

Note if the SD-JWT-VP does not contain a Holder Binding JWT, the trailing “~” character would still distinguish the SD-JWT-VP from an SD-JWT-VC.

Verifiable Presentations secured using this specification contain JSON objects. A uni-directional mapping mechanism on the W3C JSON-LD vocabulary is defined in Appendix B [TBD].

## Holder Binding JWT Claims

"iat"
REQUIRED. The time of issuance of the Holder Binding JWT.

"nonce"
REQUIRED. TBD

"aud"
REQUIRED. TBD

## Examples

The following is an example of a file containing an SD-JWT-VP.

TBD

# Security Considerations

TBD Security

# Privacy Considerations

TBD Privacy

# IANA Considerations

## JSON Web Token Claims Registration

This specification registers the Claims defined in Section TBD in the IANA JSON Web Token Claims registry defined in [JWT].

### type
TBD

### status
TBD

## Media Types Registry

### application/vc+sd-jwt

The Internet media type for a SD-JWT-VC is "application/vc+sd-jwt".

Type name: application

Subtype name:  vc+sd-jwt

Required parameters: n/a

Optional parameters: n/a

Encoding considerations: 8-bit code points; SD-JWT-VC values are encoded as a series of base64url-encoded values (some of which may be the empty string) separated by period ('.') and tilde ('~') characters.

Security considerations:

  See Security Considerations in Section TODO.

Interoperability considerations: n/a

  Published specification:
    RFC TODO

   Applications that use this media type:
      Applications that issue, present, verify verifiable credentials and presentations.

   Additional information:

      Magic number(s): n/a

      File extension(s): n/a

      Macintosh file type code(s): n/a

   Person & email address to contact for further information:
     TBD

   Intended usage: COMMON

   Restrictions on usage: none

   Author: Oliver Terbu <TODO@email.com>

   Change controller: IETF

### application/vp+sd-jwt

TBD ...

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.

# Appendix A. Additional Examples

TBD

# Appendix B. Mapping to W3C Verifiable Credentials Data Model
## Mapping Verifiable Credentials
TBD

## Mapping Verifiable Presentations
TBD

