defmodule JsonWebToken.JwsTest do
  use ExUnit.Case

  alias JsonWebToken.Jws
  alias JsonWebToken.Format.Base64Url

  doctest Jws

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
  @payload "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"

  defp plausible_jws?(jws, bytesize \\ 32) do
    parts = String.split(jws, ".")
    assert length(parts) == 3
    [_, _, encoded_mac] = parts
    assert byte_size(Base64Url.decode encoded_mac) == bytesize
  end

  test "sign/3 for HS256 does verify/3 and is plausible" do
    alg = "HS256"
    jws = Jws.sign(%{alg: alg}, @payload, @hs256_key)
    assert jws === Jws.verify(jws, alg, @hs256_key)
    plausible_jws?(jws)
  end

  test "sign/3 w/o passing a matching algorithm to verify/3 raises" do
    jws = Jws.sign(%{alg: "HS256"}, @payload, @hs256_key)
    message = "Algorithm not matching 'alg' header parameter"
    assert_raise RuntimeError, message, fn ->
      Jws.verify(jws, "RS256", @hs256_key)
    end
  end

  test "sign/3 passing alg: 'none' to verify/3 raises" do
    jws = Jws.sign(%{alg: "HS256"}, @payload, @hs256_key)
    message = "Algorithm not matching 'alg' header parameter"
    assert_raise RuntimeError, message, fn ->
      Jws.verify(jws, "none", @hs256_key)
    end
  end

  test "sign/3 w/o passing a key to verify/3 is 'Invalid'" do
    alg = "HS256"
    jws = Jws.sign(%{alg: alg}, @payload, @hs256_key)
    assert "Invalid" === Jws.verify(jws, alg, nil)
  end
end
