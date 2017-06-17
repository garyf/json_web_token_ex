defmodule JsonWebToken.Algorithm.Ecdsa do
  @moduledoc """
  Sign or verify a JSON Web Signature (JWS) structure using EDCSA

  see http://tools.ietf.org/html/rfc7518#section-3.4
  """

  alias JsonWebToken.Algorithm.Common
  alias JsonWebToken.Util

  # attr: {curve, der_byte_count_minimum_threshold}
  @sha_bits_to_attr %{
    sha256: {:secp256r1, 69},
    sha384: {:secp384r1, 101},
    sha512: {:secp521r1, 137}
  }

  @doc """
  Return a der-encoded digital signature, or Message Authentication Code (MAC)

  ## Example
      iex> {_, private_key} = EcdsaUtil.key_pair
      ...> der_encoded_mac = JsonWebToken.Algorithm.Ecdsa.sign(:sha256, private_key, "signing_input")
      ...> byte_size(der_encoded_mac) > 69
      true
  """
  def sign(sha_bits, private_key, signing_input) do
    validate_params(sha_bits, private_key)
    mac = :crypto.sign(:ecdsa, sha_bits, signing_input, [private_key, curve(sha_bits)])
    validate_signature_size(mac, sha_bits)
  end

  @doc "Named curve corresponding to sha_bits"
  def curve(sha_bits) do
    {curve, _} = @sha_bits_to_attr[sha_bits]
    curve
  end

  @doc """
  Predicate to verify a der-encoded digital signature, or Message Authentication Code (MAC)

  ## Example
      iex> {public_key, private_key} = JsonWebToken.Algorithm.EcdsaUtil.key_pair
      ...> mac = JsonWebToken.Algorithm.Ecdsa.sign(:sha256, private_key, "signing_input")
      ...> JsonWebToken.Algorithm.Ecdsa.verify?(mac, :sha256, public_key, "signing_input")
      true
  """
  def verify?(mac, sha_bits, public_key, signing_input) do
    validate_params(sha_bits, public_key)
    validate_signature_size(mac, sha_bits)
    :crypto.verify(:ecdsa, sha_bits, signing_input, mac, [public_key, curve(sha_bits)])
  end

  defp validate_params(sha_bits, key) do
    Common.validate_bits(sha_bits)
    Util.validate_present(key)
  end

  # der encoding adds at least 6 bytes to the mac
  defp validate_signature_size(der_encoded_mac, sha_bits) do
    der = Util.validate_present(der_encoded_mac)
    {_, der_byte_count_minimum_threshold} = @sha_bits_to_attr[sha_bits]
    small_der(byte_size(der) < der_byte_count_minimum_threshold)
    der_encoded_mac
  end

  defp small_der(true), do: raise "MAC too small"
  defp small_der(_), do: :ok
end
