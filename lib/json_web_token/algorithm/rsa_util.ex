defmodule JsonWebToken.Algorithm.RsaUtil do
  @moduledoc "Encryption keys for test"

  @path_to_fixtures "test/fixtures/rsa"

  @doc "Load an RSA private key from a pem file"
  def private_key(filename \\ "private_key.pem") do
    {:RSAPrivateKey, :'two-prime', n, e, d, _p, _q, _e1, _e2, _c, _other} =
      entry_decode(filename)
    [e, n, d]
  end

  @doc "Load an RSA public key from a pem file"
  def public_key(filename \\ "public_key.pem") do
    {:RSAPublicKey, n, e} = entry_decode(filename)
    [e, n]
  end

  defp entry_decode(filename) do
    pem_read(filename)
    |> :public_key.pem_decode
    |> List.first
    |> :public_key.pem_entry_decode
  end

  defp pem_read(filename) do
    Path.join(@path_to_fixtures, filename)
    |> File.read!
  end
end
