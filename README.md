# JSON Web Token [![travis][ci_img]][travis] [![hex docs][hd_img]][hex_docs]

## A JSON Web Token (JWT) implementation for Elixir

### Description
An Elixir implementation of the JSON Web Token (JWT) standard [RFC 7519][rfc7519]

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

Add JsonWebToken as a dependency in your `mix.exs` file:

```elixir
defp deps do
  [{:json_web_token, "~> 0.2"}]
end
```

### JsonWebToken.sign(claims, options)

Returns a JSON Web Token string

`claims` (required) string or map

`options` (required) map

* **alg** (optional, default: `"HS256"`)
* **key** (required unless alg is "none")

Include any JWS JOSE header parameters ([RFC 7515][rfc7515]) in the options map

Example

```elixir

# sign with default algorithm, HMAC SHA256
jwt = JsonWebToken.sign(%{foo: "bar"}, %{key: "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"})

# sign with RSA SHA256 algorithm
private_key = JsonWebToken.Algorithm.RsaUtil.private_key("path/to/", "key.pem")
opts = %{
  alg: "RS256",
  key: private_key
}

jwt = JsonWebToken.sign(%{foo: "bar"}, opts)

# unsecured token (algorithm is "none")
jwt = JsonWebToken.sign(%{foo: "bar"}, %{alg: "none"})

```

### JsonWebToken.verify(jwt, options)

Returns a tuple, either:
* \{:ok, claims\}, a JWT claims set map, if the Message Authentication Code (MAC), or signature, is verified
* \{:error, "invalid"\}, otherwise

`"jwt"` (required) is a JSON web token string

`options` (required) map

* **alg** (optional, default: `"HS256"`)
* **key** (required unless alg is "none")

Example

```elixir

secure_jwt_example = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt.cGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

# verify with default algorithm, HMAC SHA256
{:ok, claims} = JsonWebToken.verify(secure_jwt_example, %{key: "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"})

# verify with RSA SHA256 algorithm
opts = %{
  alg: "RS256",
  key: < RSA public key >
}

{:ok, claims} = JsonWebToken.verify(jwt, opts)

# unsecured token (algorithm is "none")
unsecured_jwt_example = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt."

{:ok, claims} = JsonWebToken.verify(unsecured_jwt_example, %{alg: "none"})

```

### Supported encryption algorithms

alg Param Value | Digital Signature or MAC Algorithm
------|------
HS256 | HMAC using SHA-256 per [RFC 2104][rfc2104]
HS384 | HMAC using SHA-384
HS512 | HMAC using SHA-512
RS256 | RSASSA-PKCS-v1_5 using SHA-256 per [RFC3447][rfc3447]
RS384 | RSASSA-PKCS-v1_5 using SHA-384
RS512 | RSASSA-PKCS-v1_5 using SHA-512
ES256 | ECDSA using P-256 and SHA-256 per [DSS][dss]
ES384 | ECDSA using P-384 and SHA-384
ES512 | ECDSA using P-521 and SHA-512
none | No digital signature or MAC performed (unsecured)

### Registered claim names

A companion Hex package, [JWT Claims][jwt_claims], provides support for verifying these optional, registered claim names:
* "**iss**" (Issuer)
* "**sub**" (Subject)
* "**aud**" (Audience)
* "**exp**" (Expiration Time)
* "**nbf**" (Not Before)
* "**iat**" (Issued At)
* "**jti**" (JWT ID)

### Supported Elixir versions
Elixir 1.4 and up

### Limitations
Future implementation may include these features:

- representation of a JWT as a JSON Web Encryption (JWE) [RFC 7516][rfc7516]
- OPTIONAL nested JWTs

[rfc2104]: http://tools.ietf.org/html/rfc2104
[rfc3447]: http://tools.ietf.org/html/rfc3447
[rfc7515]: http://tools.ietf.org/html/rfc7515
[rfc7516]: http://tools.ietf.org/html/rfc7516
[rfc7518]: http://tools.ietf.org/html/rfc7518
[rfc7519]: http://tools.ietf.org/html/rfc7519
[dss]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

[thomson-postel]: https://tools.ietf.org/html/draft-thomson-postel-was-wrong-00

[travis]: https://travis-ci.org/garyf/json_web_token_ex
[ci_img]: https://travis-ci.org/garyf/json_web_token_ex.svg?branch=master
[hex_docs]: http://hexdocs.pm/json_web_token
[hd_img]: http://img.shields.io/badge/docs-hexpm-blue.svg

[jwt_claims]: https://github.com/garyf/jwt_claims_ex
