defmodule JsonWebToken.Mixfile do
  use Mix.Project

  def project do
    [
      app: :json_web_token,
      version: "0.2.10",
      elixir: "~> 1.4",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      package: package(),
      description: "Elixir implementation of the JSON Web Token (JWT), RFC 7519",
      test_coverage: [tool: ExCoveralls]
    ]
  end

  # Configuration for the OTP application
  #
  # Type `mix help compile.app` for more information
  def application do
    [
      applications: [
        :crypto,
        :logger,
        :public_key
      ]
    ]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type `mix help deps` for more examples and options
  defp deps do
    [
      {:earmark, "~> 1.2", only: :dev},
      {:ex_doc, "~> 0.16", only: :dev},
      {:excoveralls, "~> 0.7", only: :test},
      {:poison, "~> 3.1"}
    ]
  end

  defp package do
    [
      maintainers: ["Gary Fleshman"],
      licenses: ["MIT"],
      links: %{github: "https://github.com/garyf/json_web_token_ex"}
    ]
  end
end
