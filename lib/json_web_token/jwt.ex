defmodule JsonWebToken.Jwt do
  @moduledoc """
  Encode claims for transmission as a JSON object that is used as the payload of a JSON Web
  Signature (JWS) structure, enabling the claims to be integrity protected with a Message
  Authentication Code (MAC), to be later verified

  see http://tools.ietf.org/html/rfc7519
  """

  alias JsonWebToken.Jws

  @algorithm_default "HS256"
  @header_default %{typ: "JWT"}
  # JOSE header types from: https://tools.ietf.org/html/rfc7515
  @header_jose_keys [:alg, :jku, :jwk, :kid, :x5u, :x5c, :x5t, :"x5t#S256", :typ, :cty, :crit]

  @doc """
  Return a JSON Web Token (JWT), a string representing a set of claims as a JSON object that is
  encoded in a JWS

  ## Example
      iex> claims = %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.Jwt.sign(claims, %{key: key})
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiZXhwIjoxMzAwODE5MzgwfQ.Ktfu3EdLz0SpuTIMpMoRZMtZsCATWJHeDEBGrsZE6LI"

  see http://tools.ietf.org/html/rfc7519#section-7.1
  """
  def sign(claims, options) do
    header = config_header(options)
    payload = claims_to_json(claims)
    jws_message(header, payload, options[:key], header[:alg])
  end

  @doc """
  Given an options map, return a map of header options

  ## Example
      iex> JsonWebToken.Jwt.config_header(alg: "RS256", key: "key")
      %{typ: "JWT", alg: "RS256"}

  Filters out unsupported claims options and ignores any encryption keys
  """
  def config_header(options) when is_map(options) do
    {jose_registered_headers, _other_headers} = Map.split(options, @header_jose_keys)

    @header_default
    |> Map.merge(jose_registered_headers)
    |> Map.merge(%{alg: algorithm(options)})
  end
  def config_header(options) when is_list(options) do
    options |> Map.new |> config_header
  end

  defp algorithm(options) do
    alg = options[:alg] || @algorithm_default
    alg_or_default(alg, alg == "")
  end

  defp alg_or_default(_, true), do: @algorithm_default
  defp alg_or_default(alg, _), do: alg

  defp claims_to_json(nil), do: raise "Claims nil"
  defp claims_to_json(""), do: raise "Claims blank"
  defp claims_to_json(claims) do
    claims
    |> Poison.encode
    |> claims_json
  end

  defp claims_json({:ok, json}), do: json
  defp claims_json({:error, _}), do: raise "Failed to encode claims as JSON"

  defp jws_message(header, payload, _, "none"), do: Jws.unsecured_message(header, payload)
  defp jws_message(header, payload, key, _), do: Jws.sign(header, payload, key)

  @doc """
  Return a tuple {ok: claims (map)} if the signature is verified, or {:error, "invalid"} otherwise

  ## Example
      iex> jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiZXhwIjoxMzAwODE5MzgwfQ.Ktfu3EdLz0SpuTIMpMoRZMtZsCATWJHeDEBGrsZE6LI"
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.Jwt.verify(jwt, %{key: key})
      {:ok, %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}}

  see http://tools.ietf.org/html/rfc7519#section-7.2
  """
  def verify(jwt, options) do
    payload(Jws.verify jwt, algorithm(options), options[:key])
  end

  defp payload({:error, "invalid"}), do: {:error, "invalid"}
  defp payload({:ok, jws}), do: {:ok, jws_payload(jws)}

  defp jws_payload(jws) do
    [_, encoded_payload, _] = String.split(jws, ".")
    payload_to_map(encoded_payload)
  end

  defp payload_to_map(encoded_payload) do
    encoded_payload
    |> Base.url_decode64!(padding: false)
    |> Poison.decode(keys: :atoms)
    |> claims_map
  end

  defp claims_map({:ok, map}), do: map
  defp claims_map({:error, _}), do: raise "Failed to decode claims from JSON"
end
