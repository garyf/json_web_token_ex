defmodule JsonWebToken.Algorithm.RsaUtilTest do
  use ExUnit.Case

  alias JsonWebToken.Algorithm.Rsa
  alias JsonWebToken.Algorithm.RsaUtil

  @path_to_keys "test/fixtures/rsa"

  test "private_key" do
    key = RsaUtil.private_key(@path_to_keys, "private_key.pem")
    assert length(key) == 3
    assert byte_size(Rsa.modulus key) == 256
  end

  test "public_key" do
    key = RsaUtil.public_key(@path_to_keys, "public_key.pem")
    assert length(key) == 2
    assert byte_size(Rsa.modulus key) == 256
  end

  test "private key with ASN.1 header" do
    key = RsaUtil.private_key(@path_to_keys, "private_key_asn1_header.pem")
    assert length(key) == 3
    assert byte_size(Rsa.modulus key) == 256
  end

  test "private key passed in directly" do
    file_key = RsaUtil.private_key(@path_to_keys, "private_key.pem")
    string_key =
      Path.join(@path_to_keys, "private_key.pem")
      |> File.read!
      |> RsaUtil.private_key
    assert file_key == string_key
  end

  test "public key passed in directly" do
    file_key = RsaUtil.public_key(@path_to_keys, "public_key.pem")
    string_key =
      Path.join(@path_to_keys, "public_key.pem")
        |> File.read!
        |> RsaUtil.public_key
    assert file_key == string_key
  end
end
