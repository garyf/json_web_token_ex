defmodule JsonWebToken.Algorithm.Rsa do
  @moduledoc """
  Sign or verify a JSON Web Signature (JWS) structure using RSASSA-PKCS-v1_5

  see http://tools.ietf.org/html/rfc7518#section-3.3
  """

  @doc """
  Return a Message Authentication Code (MAC)

  ## Example
      iex> private_key = JsonWebToken.Algorithm.RsaUtil.private_key
      ...> mac = JsonWebToken.Algorithm.Rsa.sign(:sha256, private_key, "signing_input")
      ...> byte_size(mac)
      256
  """
  def sign(sha_bits, private_key, data) do
    :crypto.sign(:rsa, sha_bits, data, private_key)
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
  def verify?(mac, sha_bits, public_key, data) do
    :crypto.verify(:rsa, sha_bits, data, mac, public_key)
  end

  @doc "RSA key modulus, n"
  def modulus(key), do: :crypto.mpint(Enum.at key, 1)
end
