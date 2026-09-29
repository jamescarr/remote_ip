defmodule RemoteIp.Strategies.RightmostTrustedRange do
  @behaviour RemoteIp.Strategy

  @moduledoc """
  Derives the client IP from the rightmost IP not in a set of trusted ranges.

  It parses every entry of the configured header, keeping track of position
  even for entries that don't resolve to an IP (see
  `RemoteIp.Strategy.positions/2`), and scans right-to-left, skipping every
  entry that resolved to an IP configured as a proxy via the `:proxies`
  option. The first remaining entry is returned - but if that entry (or any
  skipped one) didn't resolve to an IP at all, that's a misconfiguration
  (a trusted proxy should always add a valid `for=`/IP), so `nil` is returned
  instead of silently continuing past it into an earlier, less-trusted entry.

  Use this strategy when the IP ranges of every reverse proxy between the
  internet and your server are known - including any with public IPs (e.g. a
  third-party CDN/WAF such as Cloudflare). List all of those ranges in
  `:proxies`; the rightmost IP *not* in that list is the one added by the
  first proxy you control.

  Note that this strategy does *not* automatically skip loopback/private
  addresses the way `RemoteIp.Strategies.RightmostNonPrivate` does: trusted
  ranges are explicit. If an internal proxy sits in front of your server, its
  address range must be listed in `:proxies` too (or carved out with
  `:clients`).

  ## Options

    * `:header` - required; must be `"x-forwarded-for"` or `"forwarded"`.

  ## Examples

      iex> opts = [header: "x-forwarded-for"]
      iex> RemoteIp.Strategies.RightmostTrustedRange.find(
      ...>   [{"x-forwarded-for", "1.1.1.1, 2.2.2.2"}], opts)
      {2, 2, 2, 2}

  When no `:proxies` are configured, the rightmost entry is returned untouched
  (even if it is private, unlike `RemoteIp.Strategies.RightmostNonPrivate`):

      iex> opts = [header: "x-forwarded-for"]
      iex> RemoteIp.Strategies.RightmostTrustedRange.find(
      ...>   [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}], opts)
      {10, 0, 0, 1}

  A malformed or obfuscated entry halts the scan rather than being skipped
  like a trusted proxy would be:

      iex> opts = [header: "forwarded", proxies: [RemoteIp.Block.parse!("9.9.9.9/32")]]
      iex> RemoteIp.Strategies.RightmostTrustedRange.find(
      ...>   [{"forwarded", "for=6.6.6.6, for=unknown, for=9.9.9.9"}], opts)
      nil
  """

  @allowed_headers ~w[x-forwarded-for forwarded]

  @impl RemoteIp.Strategy

  def find(headers, opts) do
    headers
    |> RemoteIp.Strategy.positions(opts)
    |> Enum.reverse()
    |> skip_trusted(opts)
  end

  defp skip_trusted([], _opts), do: nil
  defp skip_trusted([:invalid | _rest], _opts), do: nil

  defp skip_trusted([{:ok, ip} | rest], opts) do
    if RemoteIp.Strategy.proxy?(ip, opts) do
      skip_trusted(rest, opts)
    else
      ip
    end
  end

  @impl RemoteIp.Strategy

  def validate(opts) do
    RemoteIp.Strategy.validate_required_header(opts, @allowed_headers)
  end
end
