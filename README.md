# JSON Web Token

## A JSON Web Token implementation for Elixir

### Description
An Elixir implementation of the JSON Web Token (JWT) Standards Track [RFC 7519][rfc7519]

### Philosophy & design goals
* Minimal API surface area
* Clear separation and conformance to underlying standards
  - JSON Web Signature (JWS) Standards Track [RFC 7515][rfc7515]
  - JSON Web Algorithms (JWA) Standards Track [RFC 7518][rfc7518]
* Thorough test coverage
* Modularity for comprehension and extensibility
* Fail fast and hard, with maximally strict validation
  - Inspired by [The Harmful Consequences of Postel's Maxim][thomson-postel]
* Implement only the REQUIRED elements of the JWT standard (initially)

## Usage

### JsonWebToken.sign(claims, options)

Returns a JSON Web Token string

`claims` (required) map

`options` (required) map

* **alg** (optional, default: `"HS256"`)
* **key** (required unless alg is "none")

### JsonWebToken.verify(jwt, options)

Returns either:
* a JWT claims set map, if the Message Authentication Code (MAC), or signature, is verified
* a string, "Invalid", otherwise

`"jwt"` (required) is a JSON web token string

`options` (required) map

* **alg** (optional, default: `"HS256"`)
* **key** (required unless alg is "none")

### Supported encryption algorithms
The 2 REQUIRED JWT algorithms

- HMAC using SHA-256 per [RFC 2104][rfc2104]
- none (unsecured)

### Supported Elixir versions
Elixir 1.0.5 and up

### Limitations
Future implementation may include these features:

- Representation of a JWT as a JSON Web Encryption (JWE) [RFC 7516][rfc7516]
- RECOMMENDED or OPTIONAL encryption algorithms
- OPTIONAL nested JWTs

[rfc2104]: http://tools.ietf.org/html/rfc2104
[rfc7515]: http://tools.ietf.org/html/rfc7515
[rfc7516]: http://tools.ietf.org/html/rfc7516
[rfc7518]: http://tools.ietf.org/html/rfc7518
[rfc7519]: http://tools.ietf.org/html/rfc7519

[thomson-postel]: https://tools.ietf.org/html/draft-thomson-postel-was-wrong-00
