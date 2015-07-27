defmodule JsonWebToken.Util do
  @moduledoc "Utility functions"

  @doc """
  Return the string passed in, unless it is nil or an empty string

  ## Example
      iex> JsonWebToken.Util.validate_present("a")
      "a"
  """
  def validate_present(param), do: validate_present(param, param == "")

  defp validate_present(nil, _), do: raise "Param nil"
  defp validate_present(_, true), do: raise "Param blank"
  defp validate_present(param, _), do: param
end
