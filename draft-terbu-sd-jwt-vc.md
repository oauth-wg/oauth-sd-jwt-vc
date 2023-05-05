%%%
title = "SD-JWT-based Verifiable Credentials with JSON payloads"
abbrev = "sd-jwt-vc"
ipr = "none"
workgroup = "TBD"
keyword = ["security", "openid", "sd-jwt"]

[seriesInfo]
name = "Internet-Draft"
value = "draft-terbu-sd-jwt-vc"
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

TBD

## Payload

TBD

### Usage of registered JWT Claims

TBD

### "status" Claim

TBD: might get removed once other draft spec finished

# Validation Rules and Processing

TBD

## Issuer Authentication

TBD

## JWT Issuer Metadata

TBD

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
