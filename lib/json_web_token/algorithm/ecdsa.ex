defmodule JsonWebToken.Algorithm.Ecdsa do
  @moduledoc """
  Sign or verify a JSON Web Signature (JWS) structure using EDCSA

  see http://tools.ietf.org/html/rfc7518#section-3.4
  """

  alias JsonWebToken.Algorithm.Common
  alias JsonWebToken.Util

  @bits_to_curves %{
    :sha256 => :secp256k1,
    :sha384 => :secp384r1,
    :sha512 => :secp521r1
  }

  @doc """
  Return a Message Authentication Code (MAC)

  ## Example
      iex> {_, private_key} = EcdsaUtil.key_pair
      ...> mac = JsonWebToken.Algorithm.Ecdsa.sign(:sha256, private_key, "signing_input")
      ...> byte_size(mac) > 64
      true
  """
  def sign(sha_bits, private_key, data) do
    validate_params(sha_bits, private_key)
    :crypto.sign(:ecdsa, sha_bits, data, [private_key, curve(sha_bits)])
  end

  @doc "Named curve corresponding to sha_bits"
  def curve(sha_bits), do: @bits_to_curves[sha_bits]

  @doc """
  Predicate to verify a digital signature, or mac

  ## Example
      iex> {public_key, private_key} = JsonWebToken.Algorithm.EcdsaUtil.key_pair
      ...> mac = JsonWebToken.Algorithm.Ecdsa.sign(:sha256, private_key, "signing_input")
      ...> JsonWebToken.Algorithm.Ecdsa.verify?(mac, :sha256, public_key, "signing_input")
      true
  """
  def verify?(mac, sha_bits, public_key, data) do
    validate_params(sha_bits, public_key)
    :crypto.verify(:ecdsa, sha_bits, data, mac, [public_key, curve(sha_bits)])
  end

  defp validate_params(sha_bits, key) do
    Common.validate_bits(sha_bits)
    Util.validate_present(key)
  end
end
