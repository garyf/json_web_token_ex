defmodule JsonWebTokenTest do
  use ExUnit.Case

  doctest JsonWebToken

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"
  @claims %{iss: "joe", exp: 1300819380, "http://example.com/is_root": true}

  defp sign_and_verify(options, claims \\ @claims) do
    jwt = JsonWebToken.sign(claims, options)
    assert claims === JsonWebToken.verify(jwt, options)
  end

  test "sign/2 jwt w default alg does verify/2" do
    sign_and_verify(%{key: @hs256_key})
  end

  test "sign/2 w HS256 alg does verify/2" do
    sign_and_verify(%{alg: "HS256", key: @hs256_key})
  end

  test "sign/2 w 'none' alg (and no key) does verify/2" do
    sign_and_verify(%{alg: "none"})
  end
end
