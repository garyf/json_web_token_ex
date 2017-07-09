defmodule JsonWebToken.Algorithm.Rsa do
  @moduledoc """
  Sign or verify a JSON Web Signature (JWS) structure using RSASSA-PKCS-v1_5

  see http://tools.ietf.org/html/rfc7518#section-3.3
  """

  alias JsonWebToken.Algorithm.Common
  alias JsonWebToken.Util

  @key_bits_min 2048

  @doc """
  Return a Message Authentication Code (MAC)

  ## Example
      iex> alias JsonWebToken.Algorithm.RsaUtil
      ...> private_key = RsaUtil.private_key("test/fixtures/rsa", "private_key.pem")
      ...> mac = JsonWebToken.Algorithm.Rsa.sign(:sha256, private_key, "signing_input")
      ...> byte_size(mac)
      256
  """
  def sign(sha_bits, private_key, signing_input) do
    validate_params(sha_bits, private_key)
    :crypto.sign(:rsa, sha_bits, signing_input, private_key)
  end

  @doc """
  Predicate to verify a digital signature, or mac

  ## Example
      iex> alias JsonWebToken.Algorithm.RsaUtil
      ...> path_to_keys = "test/fixtures/rsa"
      ...> private_key = RsaUtil.private_key(path_to_keys, "private_key.pem")
      ...> public_key = RsaUtil.public_key(path_to_keys, "public_key.pem")
      ...> mac = JsonWebToken.Algorithm.Rsa.sign(:sha256, private_key, "signing_input")
      ...> JsonWebToken.Algorithm.Rsa.verify?(mac, :sha256, public_key, "signing_input")
      true
  """
  def verify?(mac, sha_bits, public_key, signing_input) do
    validate_params(sha_bits, public_key)
    :crypto.verify(:rsa, sha_bits, signing_input, mac, public_key)
  end

  @doc "RSA key modulus, n"
  def modulus([_exponent, modulus | _rest]) do
    bytes_list = Integer.digits(modulus, 256)
    :erlang.list_to_binary(bytes_list)
  end

  defp validate_params(sha_bits, key) do
    Common.validate_bits(sha_bits)
    validate_key_size(key)
  end

  # http://tools.ietf.org/html/rfc7518#section-3.3
  defp validate_key_size(key) when is_list(key) do
    key = Util.validate_present(key) |> modulus()
    weak_key(bit_size(key) < @key_bits_min)
  end

  defp validate_key_size(key) do
    key = Util.validate_present(key)
    weak_key(bit_size(key) < @key_bits_min)
  end

  defp weak_key(true), do: raise "RSA modulus too short"
  defp weak_key(_), do: :ok
end
