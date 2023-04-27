---
title: "Verifiable Credentials using Selective Disclosure for JWTs"
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

TODO Abstract


--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

## Media Types Registry

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

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
