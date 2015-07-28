defmodule JsonWebToken.Algorithm.RsaUtilTest do
  use ExUnit.Case

  alias JsonWebToken.Algorithm.Rsa
  alias JsonWebToken.Algorithm.RsaUtil

  test "private_key" do
    key = RsaUtil.private_key
    assert length(key) == 3
    assert byte_size(Rsa.modulus key) == 261
  end

  test "public_key" do
    key = RsaUtil.public_key
    assert length(key) == 2
    assert byte_size(Rsa.modulus key) == 261
  end
end
