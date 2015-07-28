defmodule JsonWebToken.JwaTest do
  use ExUnit.Case

  alias JsonWebToken.Algorithm.RsaUtil
  alias JsonWebToken.Jwa

  doctest Jwa

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
  @rsa_private_key RsaUtil.private_key
  @rsa_public_key RsaUtil.public_key

  @signing_input "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"

  test "HS256 sign/3 does verify?/4 w 32-byte mac" do
    alg = "HS256"
    mac = Jwa.sign(alg, @hs256_key, @signing_input)
    assert Jwa.verify?(mac, alg, @hs256_key, @signing_input)
    assert byte_size(mac) == 32
  end

  test "RS256 sign/3 does verify?/4 w 256-byte mac" do
    alg = "RS256"
    mac = Jwa.sign(alg, @rsa_private_key, @signing_input)
    assert Jwa.verify?(mac, alg, @rsa_public_key, @signing_input)
    assert byte_size(mac) == 256
  end

  test "HS256 destructured_alg/1" do
    assert Jwa.destructured_alg("HS256") == {JsonWebToken.Algorithm.Hmac, :sha256}
  end

  defp invalid_algorithm(string) do
    message = "Unrecognized algorithm"
    assert_raise RuntimeError, message, fn ->
      Jwa.destructured_alg(string)
    end
  end

  test "HS257 destructured_alg/1 raises", do: invalid_algorithm("HS257")

  test "HX256 destructured_alg/1 raises", do: invalid_algorithm("HX256")
end
