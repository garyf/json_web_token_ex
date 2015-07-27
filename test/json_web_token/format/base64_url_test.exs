defmodule JsonWebToken.Format.Base64UrlTest do
  use ExUnit.Case

  alias JsonWebToken.Format.Base64Url

  doctest Base64Url

  defp decode_encoded_matches?(str) do
    encoded = Base64Url.encode(str)
    str == Base64Url.decode(encoded)
  end

  test "decode/1 encode/1 typical" do
    assert decode_encoded_matches?("{\"typ\":\"JWT\", \"alg\":\"HS256\"}")
  end

  test "decode/1 encode/1 w whitespace" do
    assert decode_encoded_matches?("{\"typ\":\"JWT\" ,  \"alg\":\"HS256\"  }")
  end

  test "decode/1 encode/1 w line feed and carriage return" do
    assert decode_encoded_matches?("{\"typ\":\"JWT\",/n \"a/rlg\":\"HS256\"}")
  end

  defp given_encoded_matches?(str, encoded) do
    Base64Url.encode(str) == encoded &&
      Base64Url.decode(encoded) == str
  end

  test "decode/1 w no padding char" do
    str = "{\"typ\":\"JWT\", \"alg\":\"none\"}"
    encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoibm9uZSJ9"
    assert given_encoded_matches?(str, encoded)
  end

  test "decode/1 w 1 padding char present" do
    str = "{\"typ\":\"JWT\", \"alg\":\"algorithm\"}"
    encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiYWxnb3JpdGhtIn0="
    assert Base64Url.decode(encoded) == str
  end

  test "decode/1 w 1 padding char removed" do
    str = "{\"typ\":\"JWT\", \"alg\":\"algorithm\"}"
    encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiYWxnb3JpdGhtIn0"
    assert given_encoded_matches?(str, encoded)
  end

  test "decode/1 w 2 padding char present" do
    str = "{\"typ\":\"JWT\", \"alg\":\"HS256\"}"
    encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiSFMyNTYifQ=="
    assert Base64Url.decode(encoded) == str
  end

  test "decode/1 w 2 padding char removed" do
    str = "{\"typ\":\"JWT\", \"alg\":\"HS256\"}"
    encoded = "eyJ0eXAiOiJKV1QiLCAiYWxnIjoiSFMyNTYifQ"
    assert given_encoded_matches?(str, encoded)
  end

  test "decode/1 w invalid encoding" do
    message = "Invalid base64 string"
    assert_raise RuntimeError, message, fn ->
      Base64Url.decode("InR5cCI6IkpXVCIsICJhbGciOiJub25lI")
    end
  end
end
