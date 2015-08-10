defmodule JsonWebToken.Algorithm.RsaUtil do
  @moduledoc "Encryption keys for test"

  @doc "Load an RSA private key from a pem file"
  def private_key(path_to_keys, filename) do
    {:RSAPrivateKey, :'two-prime', n, e, d, _p, _q, _e1, _e2, _c, _other} =
      entry_decode(path_to_keys, filename)
    [e, n, d]
  end

  @doc "Load an RSA public key from a pem file"
  def public_key(path_to_keys, filename) do
    {:RSAPublicKey, n, e} = entry_decode(path_to_keys, filename)
    [e, n]
  end

  defp entry_decode(path_to_keys, filename) do
    pem_read(path_to_keys, filename)
    |> :public_key.pem_decode
    |> List.first
    |> :public_key.pem_entry_decode
  end

  defp pem_read(path_to_keys, filename) do
    Path.join(path_to_keys, filename)
    |> File.read!
  end
end
