defmodule JsonWebToken.Algorithm.Common do
  @moduledoc "Common algorithm sha_bits validation"

  @bits_to_integer %{
    :sha256 => 256,
    :sha384 => 384,
    :sha512 => 512
  }

  def validate_bits(sha_bits), do: bits_present(@bits_to_integer[sha_bits])

  defp bits_present(nil), do: raise "Invalid sha_bits"
  defp bits_present(bits), do: bits
end
