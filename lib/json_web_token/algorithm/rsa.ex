defmodule JsonWebToken.Algorithm.Rsa do
  @moduledoc """
  Sign or verify a JSON Web Signature (JWS) structure using RSASSA-PKCS-v1_5

  see http://tools.ietf.org/html/rfc7518#section-3.3
  """

  alias JsonWebToken.Algorithm.Common
  alias JsonWebToken.Util

  @key_bits_min 2048
  @message_bytes_max 245 # 256 - 11 (per http://tools.ietf.org/html/rfc3447#section-7.2)

  @doc """
  Return a Message Authentication Code (MAC)

  ## Example
      iex> private_key = JsonWebToken.Algorithm.RsaUtil.private_key
      ...> mac = JsonWebToken.Algorithm.Rsa.sign(:sha256, private_key, "signing_input")
      ...> byte_size(mac)
      256
  """
  def sign(sha_bits, private_key, signing_input) do
    validate_params(sha_bits, private_key, signing_input)
    :crypto.sign(:rsa, sha_bits, signing_input, private_key)
  end

  @doc """
  Predicate to verify a digital signature, or mac

  ## Example
      iex> private_key = JsonWebToken.Algorithm.RsaUtil.private_key
      ...> public_key = JsonWebToken.Algorithm.RsaUtil.public_key
      ...> mac = JsonWebToken.Algorithm.Rsa.sign(:sha256, private_key, "signing_input")
      ...> JsonWebToken.Algorithm.Rsa.verify?(mac, :sha256, public_key, "signing_input")
      true
  """
  def verify?(mac, sha_bits, public_key, signing_input) do
    validate_params(sha_bits, public_key, signing_input)
    :crypto.verify(:rsa, sha_bits, signing_input, mac, public_key)
  end

  @doc "RSA key modulus, n"
  def modulus(key), do: :crypto.mpint(Enum.at key, 1)

  defp validate_params(sha_bits, key, signing_input) do
    Common.validate_bits(sha_bits)
    validate_key_size(key)
    validate_message_size(signing_input)
  end

  # http://tools.ietf.org/html/rfc7518#section-3.3
  defp validate_key_size(a_key) do
    key = Util.validate_present(a_key)
    weak_key(bit_size(modulus key) < @key_bits_min)
  end

  defp weak_key(true), do: raise "RSA modulus too short"
  defp weak_key(_), do: :ok

  # http://tools.ietf.org/html/rfc3447#section-7.2
  defp validate_message_size(signing_input) do
    message = Util.validate_present(signing_input)
    large_message(byte_size(message) > @message_bytes_max)
  end

  defp large_message(true), do: raise "Message too large"
  defp large_message(_), do: :ok
end
