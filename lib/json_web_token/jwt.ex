defmodule JsonWebToken.Jwt do
  @moduledoc """
  Encode claims for transmission as a JSON object that is used as the payload of a JSON Web
  Signature (JWS) structure, enabling the claims to be integrity protected with a Message
  Authentication Code (MAC), to be later verified

  see http://tools.ietf.org/html/rfc7519
  """

  @algorithm_default "HS256"
  @header_default %{typ: "JWT"}

  @doc """
  Given an options map, return a map of header options

  ## Example
      iex> JsonWebToken.Jwt.config_header(alg: "RS256", key: "key")
      %{typ: "JWT", alg: "RS256"}

  Filters out unsupported claims options and ignores any encryption keys
  """
  def config_header(options) do
    Dict.merge(@header_default, alg: algorithm(options))
  end

  defp algorithm(options) do
    alg = options[:alg] || @algorithm_default
    alg_or_default(alg, alg == "")
  end

  defp alg_or_default(_, true), do: @algorithm_default
  defp alg_or_default(alg, _), do: alg
end
