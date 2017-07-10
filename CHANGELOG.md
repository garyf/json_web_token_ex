## Changelog

### v0.2.10 (2017-07-09)

* bug fix
  * Properly calculate RSA modulus, thereby enabling usage of OTP 20.0

### v0.2.9 (2017-06-17)

* bug fix
  * For Ecdsa sha256, replace named curve secp256k1 with secp256r1

* enhancements
  * Update dependencies

### v0.2.8 (2017-03-04)

* bug fix
  * Handle unexpected 3 tuple return when supplying an invalid string to Poison.decode/1

* enhancements
  * Update Poison dependency

### v0.2.7 (2017-03-02)

* enhancements
  * Refactor to use Base.url_encode64

### v0.2.6 (2016-09-19)

* enhancements
  * Support JWS JOSE header parameters
  * Update dependency versions

### v0.2.5 (2016-04-14)

* enhancements
  * Update dependency versions

### v0.2.4 (2016-01-16)

* enhancements
  * Support RSA private keys encoded with ASN.1 and associated header
  * Support passing an RSA key into a function as a string
  * Update dependency versions

### v0.2.3 (2015-12-15)

* enhancements
  * README mention of jwt_claims Hex package for verifying registered claim names
  * Update dependency versions

### v0.2.2 (2015-10-06)

* enhancements
  * Elixir version ~> 1.1
  * Update dependency versions
  * README mention of jwt_claims Hex package for registered claim names

### v0.2.1 (2015-09-30)

* bug fix
  * Remove invalid RSA validate_message_size/1

### v0.2.0 (2015-08-22)

* enhancements
  * JsonWebToken, Jwt, and Jws verify/2 return values for successful verification

### v0.1.1 (2015-08-10)

* enhancements
  * Jwt and Jws verify/2 return values for failed verification
  * RsaUtil path_to_keys

### v0.1.0 (2015-08-02)

* enhancements
  * ECDSA signature validation

### v0.0.1 (2015-07-31)

* initial
  * initial release, supporting HMAC, RSASSA-PKCS-v1_5, and ECDSA encryption algorithms
