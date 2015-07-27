defmodule JsonWebToken.JwtTest do
  use ExUnit.Case

  alias JsonWebToken.Jwt

  doctest Jwt

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"

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
end
