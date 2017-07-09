defmodule JsonWebToken.Algorithm.RsaTest do
  use ExUnit.Case

  alias JsonWebToken.Algorithm.Rsa
  alias JsonWebToken.Algorithm.RsaUtil

  doctest Rsa

  @path_to_keys "test/fixtures/rsa"
  @private_key RsaUtil.private_key(@path_to_keys, "private_key.pem")
  @public_key RsaUtil.public_key(@path_to_keys, "public_key.pem")

  @signing_input_0 "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
  @signing_input_1 "{\"iss\":\"mike\",\"exp\":1300819380,\"http://example.com/is_root\":false}"

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
    public_key_alt = RsaUtil.public_key(@path_to_keys, "public_key_alt.pem")
    mac = Rsa.sign(sha_bits, @private_key, @signing_input_0)
    refute Rsa.verify?(mac, sha_bits, public_key_alt, @signing_input_0)
  end

  # param validation
  test "sign/3 w unrecognized sha_bits raises" do
    message = "Invalid sha_bits"
    assert_raise RuntimeError, message, fn ->
      Rsa.sign(:sha257, @private_key, @signing_input_0)
    end
  end

  defp invalid_key(private_key, message \\ "Param blank") do
    assert_raise RuntimeError, message, fn ->
      Rsa.sign(:sha256, private_key, @signing_input_0)
    end
  end

  test "sign/3 w private_key nil raises" do
    invalid_key(nil, "Param nil")
  end

  test "sign/3 w private_key empty string raises" do
    invalid_key("")
  end

  test "sign/3 w private_key size < key_bits_min raises" do
    # private_key_weak.pem holds a 2000-bit key
    private_key = RsaUtil.private_key(@path_to_keys, "private_key_weak.pem")
    assert byte_size(Rsa.modulus private_key) == 250
    invalid_key(private_key, "RSA modulus too short")
  end

  test "sign/3 w private_key size == key_bits_min (2048) returns a 256 byte mac" do
    signing_input = String.duplicate("a", 245)
    mac = Rsa.sign(:sha256, @private_key, signing_input)
    assert byte_size(mac) == 256
  end
end
