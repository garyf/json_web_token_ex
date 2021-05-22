defmodule JsonWebToken.Algorithm.Hmac do
  @moduledoc """
  Sign or verify a JSON Web Signature (JWS) structure using HMAC with SHA-2 algorithms

  see http://tools.ietf.org/html/rfc7518#section-3.2
  """

  alias JsonWebToken.Algorithm.Common
  alias JsonWebToken.Util

  @doc """
  Return a Message Authentication Code (MAC)

  ## Example
      iex> shared_key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.Algorithm.Hmac.sign(:sha256, shared_key, "signing_input")
      <<90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103>>
  """
  def sign(sha_bits, shared_key, signing_input) do
    validate_params(sha_bits, shared_key)
    :crypto.mac(:hmac, sha_bits, shared_key, signing_input)
  end

  @doc """
  Predicate to verify the signing_input by comparing a given `mac` to the `mac` for a newly
  signed message; comparison done in a constant-time manner to thwart timing attacks

  ## Example
      iex> mac = <<90, 34, 44, 252, 147, 130, 167, 173, 86, 191, 247, 93, 94, 12, 200, 30, 173, 115, 248, 89, 246, 222, 4, 213, 119, 74, 70, 20, 231, 194, 104, 103>>
      ...> shared_key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
      ...> JsonWebToken.Algorithm.Hmac.verify?(mac, :sha256, shared_key, "signing_input")
      true
  """
  def verify?(mac, sha_bits, shared_key, signing_input) do
    Util.constant_time_compare?(mac, sign(sha_bits, shared_key, signing_input))
  end

  defp validate_params(sha_bits, key) do
    Common.validate_bits(sha_bits)
    |> validate_key_size(key)
  end

  # http://tools.ietf.org/html/rfc7518#section-3.2
  defp validate_key_size(bits, key) do
    key = Util.validate_present(key)
    weak_key(byte_size(key) * 8 < bits)
  end

  defp weak_key(true), do: raise "Key size smaller than the hash output size"
  defp weak_key(_), do: :ok
end
