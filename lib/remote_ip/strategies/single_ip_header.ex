defmodule RemoteIp.Strategies.SingleIpHeader do
  @behaviour RemoteIp.Strategy

  @moduledoc """
  Derives the client IP from a single-IP header such as `X-Real-IP`.

  Headers like `X-Real-IP`, `CF-Connecting-IP`, and `True-Client-IP` carry a
  single IP rather than a comma-separated list. This strategy takes the *last*
  value of the configured header and parses it as one IP address - it is
  never split on commas, so a spoofed `X-Real-IP: 1.2.3.4, 5.6.7.8` resolves
  to no IP rather than picking one of the two.

  Only use this strategy for headers that are added by a trusted reverse
  proxy, and make sure that header is not spoofable by clients (e.g. Akamai's
  `True-Client-IP` requires an additional "Allow Clients To Set True Client IP
  Header: no" setting).

  ## Options

    * `:header` - required; the name of the single-IP header to read. Must
      not be `"x-forwarded-for"` or `"forwarded"` - those are list headers,
      handled by `RemoteIp.Strategies.RightmostTrustedRange` or
      `RemoteIp.Strategies.RightmostTrustedCount` instead.

  ## Examples

      iex> opts = [header: "x-real-ip"]
      iex> RemoteIp.Strategies.SingleIpHeader.find(
      ...>   [{"x-real-ip", "1.2.3.4"}], opts)
      {1, 2, 3, 4}

      iex> opts = [header: "x-real-ip"]
      iex> RemoteIp.Strategies.SingleIpHeader.find(
      ...>   [{"x-real-ip", "1.2.3.4, 5.6.7.8"}], opts)
      nil
  """

  @impl RemoteIp.Strategy

  def find(headers, opts) do
    headers
    |> RemoteIp.Strategy.take(opts)
    |> Enum.reverse()
    |> List.first()
    |> parse_ip()
  end

  defp parse_ip(nil), do: nil

  defp parse_ip({_name, value}) do
    case RemoteIp.Parsers.Generic.parse_ip(String.trim(value)) do
      {:ok, ip} -> ip
      {:error, _} -> nil
    end
  end

  @impl RemoteIp.Strategy

  def validate(opts) do
    case Keyword.get(opts, :header) do
      nil ->
        {:error, "requires a :header option"}

      header when header in ["x-forwarded-for", "forwarded"] ->
        {:error,
         ":header #{inspect(header)} is a list header; use RightmostTrustedRange or " <>
           "RightmostTrustedCount instead"}

      header ->
        if RemoteIp.Strategy.valid_header?(header) do
          :ok
        else
          {:error,
           ":header must be a non-empty, lowercase string, got #{inspect(header)}"}
        end
    end
  end
end
