defmodule RemoteIp.Strategies.LeftmostNonPrivate do
  @behaviour RemoteIp.Strategy

  @moduledoc """
  Derives the client IP from the leftmost valid, non-private IP address.

  It combines all of the IPs parsed from the configured header(s) and, scanning
  left-to-right (closest to the client first), returns the first IP that is
  neither a known proxy nor a reserved (loopback/private) address.

  This is the closest you can get to the "real" client IP, but it **MUST NOT BE
  USED FOR SECURITY PURPOSES**: the leftmost value is trivially spoofable. Use
  it only for non-security needs, such as geolocation.

  ## Options

    * `:header` - the name of a single header to process (e.g.
      `"x-forwarded-for"`). If omitted, all headers named by the `:headers`
      option are processed.

  ## Examples

      iex> opts = [header: "x-forwarded-for"]
      iex> RemoteIp.Strategies.LeftmostNonPrivate.find(
      ...>   [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}], opts)
      {1, 2, 3, 4}

      iex> opts = [header: "x-forwarded-for"]
      iex> RemoteIp.Strategies.LeftmostNonPrivate.find(
      ...>   [{"x-forwarded-for", "10.0.0.1, 2.3.4.5"}], opts)
      {2, 3, 4, 5}
  """

  @impl RemoteIp.Strategy

  def find(headers, opts) do
    headers
    |> RemoteIp.Strategy.ips(opts)
    |> Enum.find(&RemoteIp.Strategy.client?(&1, opts))
  end

  @impl RemoteIp.Strategy

  def validate(opts) do
    RemoteIp.Strategy.validate_optional_header(opts)
  end
end
