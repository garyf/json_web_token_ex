defmodule JsonWebToken.Algorithm.RsaUtil do
  @moduledoc "Encryption keys for test"

  @doc "Load an RSA private key from a string"
  def private_key(key) do
    {:RSAPrivateKey, :'two-prime', n, e, d, _p, _q, _e1, _e2, _c, _other} =
      entry_decode(key)
    [e, n, d]
  end

  @doc "Load an RSA private key from a pem file"
  def private_key(path_to_keys, filename) do
    pem_read(path_to_keys, filename)
    |> private_key
  end

  @doc "Load an RSA public key from a string"
  def public_key(key) do
    {:RSAPublicKey, n, e} = entry_decode(key)
    [e, n]
  end

  @doc "Load an RSA public key from a pem file"
  def public_key(path_to_keys, filename) do
    pem_read(path_to_keys, filename)
    |> public_key
  end

  defp entry_decode(key) do
    key
    |> :public_key.pem_decode
    |> List.first
    |> :public_key.pem_entry_decode
    |> asn1_decode
  end

  defp asn1_decode({:PrivateKeyInfo, _, _, der_key, _}) do
    :public_key.der_decode(:RSAPrivateKey, der_key)
  end
  defp asn1_decode(der), do: der

  defp pem_read(path_to_keys, filename) do
    Path.join(path_to_keys, filename)
    |> File.read!
  end
end
