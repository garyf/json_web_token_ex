defmodule JsonWebToken.Algorithm.RsaTest do
  use ExUnit.Case

  alias JsonWebToken.Algorithm.Rsa
  alias JsonWebToken.Algorithm.RsaUtil

  doctest Rsa

  @private_key RsaUtil.private_key
  @public_key RsaUtil.public_key

  @signing_input_0 "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
  @signing_input_1 "{\"iss\":\"mike\",\"exp\":1300819380,\"http://example.com/is_root\":true}"

  defp detect_changed_input_or_mac(sha_bits) do
    mac_0 = Rsa.sign(sha_bits, @private_key, @signing_input_0)
    assert Rsa.verify?(mac_0, sha_bits, @public_key, @signing_input_0)
    refute Rsa.verify?(mac_0, sha_bits, @public_key, @signing_input_1)

    mac_1 = Rsa.sign(sha_bits, @private_key, @signing_input_1)
    refute Rsa.verify?(mac_1, sha_bits, @public_key, @signing_input_0)
    assert Rsa.verify?(mac_1, sha_bits, @public_key, @signing_input_1)
  end

  test "RS256 sign/3 does verify?/4", do: detect_changed_input_or_mac(:sha256)

  test "RS384 sign/3 does verify?/4", do: detect_changed_input_or_mac(:sha384)

  test "RS512 sign/3 does verify?/4", do: detect_changed_input_or_mac(:sha512)

  test "changed key does not verify?/4" do
    sha_bits = :sha256
    public_key_alt = RsaUtil.public_key("public_key_alt.pem")
    mac = Rsa.sign(sha_bits, @private_key, @signing_input_0)
    refute Rsa.verify?(mac, sha_bits, public_key_alt, @signing_input_0)
  end
end
