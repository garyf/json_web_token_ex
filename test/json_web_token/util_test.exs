defmodule JsonWebToken.UtilTest do
  use ExUnit.Case

  alias JsonWebToken.Util

  doctest Util

  test "constant_time_compare?/2 w equivalent strings" do
    assert Util.constant_time_compare?("ab", "ab")
  end

  test "constant_time_compare?/2 w different strings" do
    refute Util.constant_time_compare?("ab", "Ab")
  end

  test "constant_time_compare?/2 w nil or empty strings returns false" do
    refute Util.constant_time_compare?(nil, nil)
    refute Util.constant_time_compare?("", "")
  end

  test "validate_present/1 w string" do
    assert Util.validate_present("foo") === "foo"
  end

  test "validate_present/1 w nil" do
    message = "Param nil"
    assert_raise RuntimeError, message, fn ->
      Util.validate_present(nil)
    end
  end

  test "validate_present/1 w empty string" do
    message = "Param blank"
    assert_raise RuntimeError, message, fn ->
      Util.validate_present("")
    end
  end
end
