defmodule JsonWebToken.Jwa do
  @moduledoc """
  Choose a cryptographic algorithm to be used for a JSON Web Signature (JWS)

  see http://tools.ietf.org/html/rfc7518
  """

  alias JsonWebToken.Algorithm.Hmac

  @algorithms ~r{(HS)(256|384|512)?}i

  @doc """
  Return a tuple with a valid encryption alg and sha_bits; raise if `string` is not a supported algorithm

  ## Example
      iex> JsonWebToken.Jwa.destructured_alg("HS256")
      {"hs", "256"}
  """
  def destructured_alg(string) do
    validated_alg(Regex.run(@algorithms, string))
  end

  defp validated_alg(captures) when length(captures) == 3 do
    [_, alg, sha_bits] = captures
    {
      String.downcase(alg),
      sha_bits
    }
  end
  defp validated_alg(_), do: raise "Unrecognized algorithm"
end
