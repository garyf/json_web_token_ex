defmodule JsonWebToken.Jwa do
  @moduledoc """
  Choose a cryptographic algorithm to be used for a JSON Web Signature (JWS)

  see http://tools.ietf.org/html/rfc7518
  """

  alias JsonWebToken.Algorithm.Ecdsa
  alias JsonWebToken.Algorithm.Hmac
  alias JsonWebToken.Algorithm.Rsa

  @algorithms ~r{(HS|RS|ES)(256|384|512)?}i

  @doc """
  Return a Message Authentication Code (MAC) for a particular `algorithm`

  ## Example
      iex> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.Jwa.sign("HS256", key, "signing_input")
      <<90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103>>
  """
  def sign(algorithm, key, signing_input) do
    {module, sha_bits} = destructured_alg(algorithm)
    apply(module, :sign, [sha_bits, key, signing_input])
  end

  @doc """
  Predicate to validate that `mac` does verify by `algorithm`

  ## Example
      iex> mac = <<90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103>>
      ...> key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.Jwa.verify?(mac, "HS256", key, "signing_input")
      true
  """
  def verify?(mac, algorithm, key, signing_input) do
    {module, sha_bits} = destructured_alg(algorithm)
    apply(module, :verify?, [mac, sha_bits, key, signing_input])
  end

  @doc """
  Return a tuple with a valid encryption module and sha_bits; raise if `string` is not a supported algorithm

  ## Example
      iex> JsonWebToken.Jwa.destructured_alg("HS256")
      {JsonWebToken.Algorithm.Hmac, :sha256}
  """
  def destructured_alg(string) do
    validated_alg(Regex.run(@algorithms, string))
  end

  defp validated_alg(captures) when length(captures) == 3 do
    [_, alg, sha_bits] = captures
    {
      alg_module(String.downcase alg),
      sha_prefixed(sha_bits)
    }
  end
  defp validated_alg(_), do: raise "Unrecognized algorithm"

  defp alg_module("hs"), do: Hmac
  defp alg_module("rs"), do: Rsa
  defp alg_module("es"), do: Ecdsa

  defp sha_prefixed(sha_bits), do: String.to_atom("sha" <> sha_bits)
end
