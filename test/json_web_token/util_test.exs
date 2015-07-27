defmodule JsonWebToken.UtilTest do
  use ExUnit.Case

  alias JsonWebToken.Util

  doctest Util

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
