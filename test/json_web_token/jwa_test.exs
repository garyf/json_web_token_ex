defmodule JsonWebToken.JwaTest do
  use ExUnit.Case

  alias JsonWebToken.Jwa

  doctest Jwa

  @hs256_key "gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr9C"

  @signing_input "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"

  test "HS256 destructured_alg/1" do
    assert Jwa.destructured_alg("HS256") == {"hs", "256"}
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
