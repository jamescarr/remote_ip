defmodule RemoteIp.Strategies.RightmostNonPrivate do
  @behaviour RemoteIp.Strategy

  @moduledoc """
  Derives the client IP from the rightmost valid, non-private IP address.

  This is the default strategy. It combines all of the IPs parsed from the
  configured header(s) and, scanning right-to-left (nearest the server first),
  returns the first IP that is neither a known proxy nor a reserved
  (loopback/private) address.

  It is the secure default when every reverse proxy between the internet and
  your server has a private/internal IP address: the rightmost non-private IP
  is the one appended by the first proxy you control.

  ## Options

    * `:header` - the name of a single header to process (e.g.
      `"x-forwarded-for"`). If omitted, all headers named by the `:headers`
      option are processed.

  ## Examples

      iex> opts = [header: "x-forwarded-for"]
      iex> RemoteIp.Strategies.RightmostNonPrivate.find(
      ...>   [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}], opts)
      {1, 2, 3, 4}
  """

  @impl RemoteIp.Strategy

  def find(headers, opts) do
    headers
    |> RemoteIp.Strategy.ips(opts)
    |> Enum.reverse()
    |> Enum.find(&RemoteIp.Strategy.client?(&1, opts))
  end

  @impl RemoteIp.Strategy

  def validate(opts) do
    RemoteIp.Strategy.validate_optional_header(opts)
  end
end
