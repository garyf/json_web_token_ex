defmodule JsonWebToken do
  @moduledoc """
  Top level interface, or API, for signing and verifying a JSON Web Token (JWT)

  see http://tools.ietf.org/html/rfc7519
  """

  alias JsonWebToken.Jwt

  @doc """
  Return a JSON Web Token (JWT), a string representing a set of claims as a JSON object that is
  encoded in a JWS

  ## Example
      iex> claims = %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.sign(claims, %{key: key})
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiZXhwIjoxMzAwODE5MzgwfQ.Ktfu3EdLz0SpuTIMpMoRZMtZsCATWJHeDEBGrsZE6LI"

  see http://tools.ietf.org/html/rfc7519#section-7.1
  """
  def sign(claims, options), do: Jwt.sign(claims, options)

  @doc """
  Return a tuple {:ok, claims (map)} if the JWT signature is verified,
  or {:error, "invalid"} otherwise

  ## Example
      iex> jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiZXhwIjoxMzAwODE5MzgwfQ.Ktfu3EdLz0SpuTIMpMoRZMtZsCATWJHeDEBGrsZE6LI"
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.verify(jwt, %{key: key})
      {:ok, %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}}

  see http://tools.ietf.org/html/rfc7519#section-7.2
  """
  def verify(jwt, options), do: Jwt.verify(jwt, options)
end
