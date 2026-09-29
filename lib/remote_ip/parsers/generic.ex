defmodule RemoteIp.Parsers.Generic do
  @behaviour RemoteIp.Parser

  @moduledoc """
  Generic parser for forwarding headers.

  This module implements the `RemoteIp.Parser` behaviour. When there is not a
  more specific parser, `RemoteIp.Headers.parse/1` falls back to using this
  one.

  The value is parsed simply as a comma-separated list of IPs. This is suitable
  for a wide range of headers, such as `X-Forwarded-For`, `X-Real-IP`, and
  `X-Client-IP`.

  Any amount of whitespace is allowed before and after the commas, as well as
  at the beginning & end of the input.

  ## Examples

      iex> RemoteIp.Parsers.Generic.parse("1.2.3.4, 5.6.7.8")
      [{1, 2, 3, 4}, {5, 6, 7, 8}]

      iex> RemoteIp.Parsers.Generic.parse("  ::1  ")
      [{0, 0, 0, 0, 0, 0, 0, 1}]

      iex> RemoteIp.Parsers.Generic.parse("invalid")
      []
  """

  @impl RemoteIp.Parser

  def parse(header) do
    header |> split_commas() |> parse_ips()
  end

  defp split_commas(header) do
    header |> String.trim() |> String.split(~r/\s*,\s*/)
  end

  defp parse_ips(strings) do
    List.foldr(strings, [], fn string, ips ->
      case parse_ip(string) do
        {:ok, ip} -> [ip | ips]
        {:error, _} -> ips
      end
    end)
  end

  @doc """
  Parses a single IP address string.

  This is the per-item primitive behind `parse/1`: it does not split on
  commas, so it should be given one already-separated token. Exposed so other
  parts of `RemoteIp` (such as strategies that need to know the *position* of
  each item, not just the final flat list of valid IPs) can reuse the same
  parsing logic instead of duplicating it.

  ## Examples

      iex> RemoteIp.Parsers.Generic.parse_ip("1.2.3.4")
      {:ok, {1, 2, 3, 4}}

      iex> RemoteIp.Parsers.Generic.parse_ip("nope")
      {:error, :einval}
  """

  def parse_ip(string) do
    try do
      :inet.parse_strict_address(string |> to_charlist())
    rescue
      UnicodeConversionError -> {:error, :invalid_unicode}
    end
  end
end
