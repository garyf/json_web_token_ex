defmodule JsonWebToken.Format.Base64Url do
  @moduledoc """
  Provide base64url encoding and decoding functions without padding, based upon standard base64 encoding
  and decoding functions that do use padding

  see http://tools.ietf.org/html/rfc7515#appendix-C
  """

  @doc """
  Given a string, return a url_encode64 string with all trailing "=" padding removed

  ## Example
      iex> JsonWebToken.Format.Base64Url.encode("foo")
      "Zm9v"
  """
  def encode(string) do
    string
    |> Base.url_encode64
    |> base64_padding_removed
  end

  defp base64_padding_removed(encoded), do: String.rstrip(encoded, ?=)

  @doc """
  Given a string encoded as url_encode64, add trailing "=" padding and return a decoded string

  ## Example
      iex> JsonWebToken.Format.Base64Url.decode("YmFy")
      "bar"

  The number of "=" padding characters that need to be added to the end of a url_encode64-encoded
  string without padding to turn it into one with padding is a deterministic function of the length
  of the encoded string.
  """
  def decode(string) do
    string
    |> base64_padding_added
    |> Base.url_decode64!
  end

  defp base64_padding_added(str) do
    mod = rem(String.length(str), 4)
    str <> padding(mod)
  end

  defp padding(0), do: ""
  defp padding(1), do: raise "Invalid base64 string"
  defp padding(mod), do: String.duplicate("=", (4 - mod))
end
