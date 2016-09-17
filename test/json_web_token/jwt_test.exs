defmodule JsonWebToken.JwtTest do
  use ExUnit.Case

  alias JsonWebToken.Jwt

  doctest Jwt

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
  @key_id "test-key"
  @claims %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}

  defp sign_does_verify(options, claims \\ @claims) do
    jwt = Jwt.sign(claims, options)
    {:ok, verified_claims} = Jwt.verify(jwt, options)
    assert verified_claims === @claims
  end

  test "sign/2 w default alg (HS256) does verify/2" do
    sign_does_verify(%{key: @hs256_key})
  end

  test "sign/2 w explicit alg does verify/2" do
    sign_does_verify(%{alg: "HS256", key: @hs256_key})
  end

  test "sign/2 w explicit alg and wrong key returns error" do
    wrong_key = "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9Z"
    options = %{alg: "HS256", key: @hs256_key}
    jwt = Jwt.sign(@claims, options)
    assert {:error, "invalid"} == Jwt.verify(jwt, %{alg: "HS256", key: wrong_key})
  end

  test "sign/2 w alg nil does verify/2" do
    sign_does_verify(%{alg: nil, key: @hs256_key})
  end

  test "sign/2 w alg empty string does verify/2" do
    sign_does_verify(%{alg: "", key: @hs256_key})
  end

  test "sign/2 w alg 'none' does verify/2" do
    sign_does_verify(%{alg: "none"})
  end

  test "sign/2 w claims nil raises" do
    message = "Claims nil"
    assert_raise RuntimeError, message, fn ->
      Jwt.sign(nil, key: @hs256_key)
    end
  end

  test "sign/2 w claims empty string raises" do
    message = "Claims blank"
    assert_raise RuntimeError, message, fn ->
      Jwt.sign("", key: @hs256_key)
    end
  end

  test "config_header/1 w key, w/o alg returns default alg and filters key" do
    assert Jwt.config_header(key: @hs256_key) == %{typ: "JWT", alg: "HS256"}
  end

  test "config_header/1 w key, w alg returns alg and filters key" do
    assert Jwt.config_header(alg: "RS256", key: "rs_256_key") == %{typ: "JWT", alg: "RS256"}
  end

  test "config_header/1 w key, w alg empty string returns default alg" do
    assert Jwt.config_header(alg: "", key: @hs256_key) == %{typ: "JWT", alg: "HS256"}
  end

  test "config_header/1 w key, w alg nil returns default alg" do
    assert Jwt.config_header(alg: nil, key: @hs256_key) == %{typ: "JWT", alg: "HS256"}
  end

  test "config_header/1 w/o key, w alg 'none'" do
    assert Jwt.config_header(alg: "none") == %{typ: "JWT", alg: "none"}
  end

  test "config_header/1 with key and key id includes the key id" do
    assert Jwt.config_header(key: @hs256_key, kid: @key_id) == %{typ: "JWT", alg: "HS256", kid: "test-key"}
  end

  test "config_header/1 excludes header that is not registered" do
    assert Jwt.config_header(key: @hs256_key, notstandard: "value") == %{typ: "JWT", alg: "HS256"} 
  end
end
