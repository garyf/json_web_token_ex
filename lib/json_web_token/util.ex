defmodule JsonWebToken.Util do
  @moduledoc "Utility functions"

  @doc """
  Predicate that compares two strings for equality in constant-time to avoid timing attacks

  ## Example
      iex> JsonWebToken.Util.constant_time_compare?("a", "A")
      false

  see: https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40#section-3.2
  """
  def constant_time_compare?(a, b) when is_nil(a) or is_nil(b) or a == "" or b == "", do: false
  def constant_time_compare?(a, b), do: secure_compare(a, b)

  # cf. hex_web lib/hex_web/util.ex
  defp secure_compare(left, right) when byte_size(left) == byte_size(right) do
    arithmetic_compare(left, right, 0) == 0
  end
  defp secure_compare(_, _), do: false

  defp arithmetic_compare(<<x, left :: binary>>, <<y, right :: binary>>, acc) do
    import Bitwise
    arithmetic_compare(left, right, acc ||| (x ^^^ y))
  end
  defp arithmetic_compare("", "", acc), do: acc

  @doc """
  Return the parameter passed in, unless it is nil or an empty string

  ## Example
      iex> JsonWebToken.Util.validate_present("a")
      "a"
  """
  def validate_present(nil), do: raise "Param nil"
  def validate_present(""), do: raise "Param blank"
  def validate_present(param), do: param
end
