defmodule JsonWebToken.Algorithm.EcdsaTest do
  use ExUnit.Case

  alias JsonWebToken.Algorithm.Ecdsa
  alias JsonWebToken.Algorithm.EcdsaUtil

  doctest Ecdsa

  @key_pair_256k1 EcdsaUtil.key_pair

  @signing_input_0 "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}"
  @signing_input_1 "{\"iss\":\"mike\",\"exp\":1300819380,\"http://example.com/is_root\":true}"

  test "ES256 sign/3 returns a mac (der encoded) w a byte_size > 68" do
    {_, private_key} = @key_pair_256k1
    mac = Ecdsa.sign(:sha256, private_key, @signing_input_0)
    assert byte_size(mac) > 68
  end

  defp detect_changed_input_or_mac(sha_bits, der_byte_count_threshold) do
    {public_key, private_key} = EcdsaUtil.key_pair(sha_bits)

    mac_0 = Ecdsa.sign(sha_bits, private_key, @signing_input_0)
    assert Ecdsa.verify?(mac_0, sha_bits, public_key, @signing_input_0)
    refute Ecdsa.verify?(mac_0, sha_bits, public_key, @signing_input_1)

    mac_1 = Ecdsa.sign(sha_bits, private_key, @signing_input_1)
    refute Ecdsa.verify?(mac_1, sha_bits, public_key, @signing_input_0)
    assert Ecdsa.verify?(mac_1, sha_bits, public_key, @signing_input_1)

    assert byte_size(mac_0) > der_byte_count_threshold
    assert byte_size(mac_1) > der_byte_count_threshold
  end

  test "ES256 sign/3 and verify?/4", do: detect_changed_input_or_mac(:sha256, 68) # 64 decoded

  test "ES384 sign/3 and verify?/4", do: detect_changed_input_or_mac(:sha384, 100) # 96

  test "ES512 sign/3 and verify?/4", do: detect_changed_input_or_mac(:sha512, 136) # 132

  test "changed key returns verify?/4 false" do
    {_, private_key} = @key_pair_256k1
    {other_public_key, _} = EcdsaUtil.key_pair

    sha_bits = :sha256
    mac = Ecdsa.sign(sha_bits, private_key, @signing_input_0)
    refute Ecdsa.verify?(mac, sha_bits, other_public_key, @signing_input_0)
  end
end
