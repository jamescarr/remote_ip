defmodule RemoteIp.Strategies.RightmostTrustedCount do
  @behaviour RemoteIp.Strategy

  @moduledoc """
  Derives the client IP from the valid IP added by the first trusted proxy.

  It parses every entry of the configured header, keeping track of position
  even for entries that don't resolve to an IP (see `RemoteIp.Strategy.positions/2`),
  and returns the IP at a fixed position from the right, based on a known
  number of trusted reverse proxies that append IPs to the header.

  With `count` trusted proxies, the client IP is the `count`-th entry from the
  right. For example, with `count: 1` it returns the rightmost entry; with
  `count: 2`, the second from the right; and so on. It returns `nil` if there
  are fewer entries than required, or if the targeted entry didn't resolve to
  an IP (a misconfiguration: either `count` is wrong, or the first trusted
  proxy didn't add a valid `for=`/IP).

  ## Options

    * `:header` - required; must be `"x-forwarded-for"` or `"forwarded"`.
    * `:count` - the positive number of trusted proxies appending to the
      header. Defaults to `1`.

  ## Examples

      iex> opts = [header: "x-forwarded-for", count: 2]
      iex> RemoteIp.Strategies.RightmostTrustedCount.find(
      ...>   [{"x-forwarded-for", "1.2.3.4, 10.0.0.1, 10.0.0.2"}], opts)
      {10, 0, 0, 1}

      iex> opts = [header: "x-forwarded-for", count: 4]
      iex> RemoteIp.Strategies.RightmostTrustedCount.find(
      ...>   [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}], opts)
      nil

  A trusted proxy is allowed to obfuscate the hop before it (RFC 7239 section
  6.3) - here the 2nd of 2 trusted proxies hides the 1st proxy's IP, but the
  1st proxy's own append (the real client) is untouched, so `count: 2` still
  resolves it:

      iex> opts = [header: "forwarded", count: 2]
      iex> RemoteIp.Strategies.RightmostTrustedCount.find(
      ...>   [{"forwarded", "for=6.6.6.6, for=2.2.2.2, for=_hidden"}], opts)
      {2, 2, 2, 2}

  But if the entry `count` actually points at is the one that's obfuscated or
  malformed, that's a misconfiguration - reindexing past it would silently
  hand back an earlier, less-trusted entry, so this returns `nil` instead:

      iex> opts = [header: "forwarded", count: 2]
      iex> RemoteIp.Strategies.RightmostTrustedCount.find(
      ...>   [{"forwarded", "for=6.6.6.6, for=_hidden, for=2.2.2.2"}], opts)
      nil
  """

  @allowed_headers ~w[x-forwarded-for forwarded]

  @impl RemoteIp.Strategy

  def find(headers, opts) do
    positions = RemoteIp.Strategy.positions(headers, opts)
    count = Keyword.get(opts, :count, 1)
    index = length(positions) - count

    if index >= 0 do
      case Enum.at(positions, index) do
        {:ok, ip} -> ip
        :invalid -> nil
      end
    end
  end

  @impl RemoteIp.Strategy

  def validate(opts) do
    with :ok <-
           RemoteIp.Strategy.validate_required_header(opts, @allowed_headers) do
      validate_count(opts)
    end
  end

  defp validate_count(opts) do
    case Keyword.get(opts, :count, 1) do
      count when is_integer(count) and count > 0 ->
        :ok

      count ->
        {:error, ":count must be a positive integer, got #{inspect(count)}"}
    end
  end
end
