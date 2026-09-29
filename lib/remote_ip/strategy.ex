defmodule RemoteIp.Strategy do
  import RemoteIp.Debugger

  @moduledoc """
  Defines the interface for resolving the remote IP from forwarding headers.

  Each strategy is a module that implements the `c:find/2` and `c:validate/1`
  callbacks, receiving the raw request headers and the unpacked options (see
  `RemoteIp.Options`). The built-in strategies live under `RemoteIp.Strategies`:

    * `RemoteIp.Strategies.RightmostNonPrivate`
    * `RemoteIp.Strategies.LeftmostNonPrivate`
    * `RemoteIp.Strategies.RightmostTrustedRange`
    * `RemoteIp.Strategies.RightmostTrustedCount`
    * `RemoteIp.Strategies.SingleIpHeader`
    * `RemoteIp.Strategies.Chain`

  but you can implement your own by `@behaviour`-ing this module.

  A strategy is configured via the `:strategy` option, given either as a bare
  module or a `{module, options}` tuple:

      plug RemoteIp, strategy: {RemoteIp.Strategies.RightmostTrustedRange,
                                header: "x-forwarded-for"}

  For more details on the available strategies, see each module's own
  documentation and the [algorithm](algorithm.md) document.
  """

  @typedoc "Any module that implements the `RemoteIp.Strategy` behaviour."

  @type t() :: module()

  @typedoc """
  A strategy spec: either a bare module or a `{module, options}` tuple.
  """

  @type spec() :: t() | {t(), keyword()}

  @typedoc """
  The options passed to `c:find/2`, combining the unpacked `RemoteIp.Options`
  with the strategy's own options.
  """

  @type options() :: keyword()

  @typedoc "A parsed IP address (see `t::inet.ip_address/0`)."

  @type ip() :: :inet.ip_address()

  @typedoc """
  The result of parsing one position in a header, as returned by
  `positions/2`: either the IP found there, or `:invalid` if that position
  didn't resolve to exactly one IP address.
  """

  @type position() :: {:ok, ip()} | :invalid

  @doc """
  Finds the remote IP from the given headers.

  `headers` is the full list of request headers (`Plug.Conn` `req_headers`).
  `options` combines the unpacked plug options (such as `:proxies`,
  `:clients`, `:parsers`, and `:headers`) with any options specific to the
  strategy (such as `:header` or `:count`). By the time `find/2` is reached
  through the plug or `RemoteIp.from/2`, `options` has already passed
  `c:validate/1`.

  Should return an `t:ip/0`, or `nil` if the strategy cannot determine one.
  """

  @callback find(headers :: Plug.Conn.headers(), options()) :: ip() | nil

  @doc """
  Validates the strategy's own options.

  Called whenever the `:strategy` option is processed (see
  `RemoteIp.Options`) - at `c:Plug.init/1` time for a literal spec, or on
  first use for a spec sourced from an MFA. `options` are the strategy's own
  options exactly as given (before merging with the plug's global options).

  Return `:ok` if `options` are usable, or `{:error, message}` with a
  human-readable reason otherwise. An invalid strategy raises `ArgumentError`
  at configuration time rather than silently misbehaving on every request.
  """

  @callback validate(options()) :: :ok | {:error, String.t()}

  # https://en.wikipedia.org/wiki/Loopback
  # https://en.wikipedia.org/wiki/Private_network
  # https://en.wikipedia.org/wiki/Reserved_IP_addresses
  @reserved ~w[
    127.0.0.0/8
    ::1/128
    fc00::/7
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
  ] |> Enum.map(&RemoteIp.Block.parse!/1)

  # `:header`/`:parsers`/`:proxies`/`:clients`/`:strategy` are plug-wide
  # options. Allowing them inside a strategy's own opts would silently bypass
  # `RemoteIp.Options.evaluate/2` (e.g. raw CIDR strings never becoming
  # `RemoteIp.Block`s) or replace rather than merge the default parsers, so
  # `validate_spec/1` rejects them up front instead of failing on every
  # request.
  @reserved_keys ~w[headers parsers proxies clients strategy]a

  @doc """
  Selects the headers a strategy should process.

  If the strategy specifies a `:header`, only headers with that name are
  returned. Otherwise, it falls back to the `:headers` option (which itself
  defaults to all of the common forwarding headers).
  """

  @spec take(Plug.Conn.headers(), options()) :: Plug.Conn.headers()

  def take(headers, opts) do
    debug :forwarding do
      debug(:headers, do: headers) |> RemoteIp.Headers.take(header_names(opts))
    end
  end

  @doc """
  Parses the given headers into a flat list of IP addresses.

  See `RemoteIp.Headers.parse/2`.
  """

  @spec parse(Plug.Conn.headers(), options()) :: [ip()]

  def parse(headers, opts) do
    debug :ips do
      parsers = Keyword.get(opts, :parsers, RemoteIp.Options.default(:parsers))
      RemoteIp.Headers.parse(headers, parsers)
    end
  end

  @doc """
  Selects and parses the headers a strategy should process, returning the
  flat list of IP addresses in routing order (leftmost first).
  """

  @spec ips(Plug.Conn.headers(), options()) :: [ip()]

  def ips(headers, opts) do
    headers |> take(opts) |> parse(opts)
  end

  @doc """
  Like `ips/2`, but preserves the position of every entry, including ones
  that don't resolve to an IP, instead of silently dropping them.

  Dropping an unparseable entry would shift every entry after it - the one at
  the 2nd position from the right is no longer the 2nd position if the 3rd
  quietly vanished. This is what `RemoteIp.Strategies.RightmostTrustedCount`
  and `RemoteIp.Strategies.RightmostTrustedRange` use instead of `ips/2`, so a
  malformed or obfuscated (RFC 7239 section 6.3) entry can't be mistaken for
  one that was never there.

  Only understands the `"x-forwarded-for"` and `"forwarded"` header formats;
  `opts[:header]` must be one of those two.

  ## Examples

      iex> RemoteIp.Strategy.positions(
      ...>   [{"x-forwarded-for", "1.2.3.4, nope, 2.3.4.5"}],
      ...>   header: "x-forwarded-for")
      [{:ok, {1, 2, 3, 4}}, :invalid, {:ok, {2, 3, 4, 5}}]

      iex> RemoteIp.Strategy.positions(
      ...>   [{"forwarded", "for=1.2.3.4, for=unknown, for=2.3.4.5"}],
      ...>   header: "forwarded")
      [{:ok, {1, 2, 3, 4}}, :invalid, {:ok, {2, 3, 4, 5}}]
  """

  @spec positions(Plug.Conn.headers(), options()) :: [position()]

  def positions(headers, opts) do
    header = Keyword.fetch!(opts, :header)

    headers
    |> take(opts)
    |> Enum.flat_map(fn {_name, value} -> positions_for(header, value) end)
  end

  defp positions_for("forwarded", value) do
    RemoteIp.Parsers.Forwarded.parse_positions(value)
  end

  defp positions_for(_xff, value) do
    value
    |> String.trim()
    |> String.split(~r/\s*,\s*/)
    |> Enum.map(fn token ->
      case RemoteIp.Parsers.Generic.parse_ip(token) do
        {:ok, ip} -> {:ok, ip}
        {:error, _} -> :invalid
      end
    end)
  end

  @doc """
  Whether the given IP should be considered a client by [the
  algorithm](algorithm.md).

  An IP is a client if it was explicitly configured in `:clients`, or if it is
  neither a configured `:proxies` address nor a reserved (loopback/private)
  address.
  """

  @spec client?(ip(), options()) :: boolean()

  def client?(ip, opts) do
    type(ip, opts) in [:client, :unknown]
  end

  @doc """
  Whether the given IP was explicitly configured as a proxy in `:proxies`.
  """

  @spec proxy?(ip(), options()) :: boolean()

  def proxy?(ip, opts) do
    type(ip, opts) == :proxy
  end

  @doc """
  Classifies an IP as `:client`, `:proxy`, `:reserved`, or `:unknown`.

  Precedence matters: `:clients` beats `:proxies`, which beats the reserved
  (loopback/private) address ranges. Anything else is `:unknown`.
  """

  @spec type(ip(), options()) :: :client | :proxy | :reserved | :unknown

  def type(ip, opts) do
    debug :type, [ip] do
      ip = RemoteIp.Block.encode(ip)
      clients = Keyword.get(opts, :clients, [])
      proxies = Keyword.get(opts, :proxies, [])

      cond do
        clients |> contains?(ip) -> :client
        proxies |> contains?(ip) -> :proxy
        @reserved |> contains?(ip) -> :reserved
        true -> :unknown
      end
    end
  end

  @doc false

  @spec normalize_spec(spec()) :: {t(), keyword()}

  def normalize_spec({module, opts}) when is_atom(module) and is_list(opts),
    do: {module, opts}

  def normalize_spec(module) when is_atom(module), do: {module, []}

  @doc """
  Normalizes and validates a strategy spec, per `c:validate/1`.

  Returns `{:ok, {module, options}}` if `spec` is a module (or `{module,
  options}` tuple) whose options don't include any of the plug-wide options
  (#{inspect(@reserved_keys)} - set those at the top level instead) and pass
  the module's own `c:validate/1`. Otherwise returns `{:error, message}`.

  Used by `RemoteIp.Options` for the top-level `:strategy` option, and by
  `RemoteIp.Strategies.Chain` for each of its `:strategies`.
  """

  @spec validate_spec(term()) :: {:ok, {t(), keyword()}} | {:error, String.t()}

  def validate_spec({module, opts}) when is_atom(module) and is_list(opts) do
    do_validate(module, opts)
  end

  def validate_spec(module) when is_atom(module) do
    do_validate(module, [])
  end

  def validate_spec(other) do
    {:error,
     "expected a strategy module or {module, options}, got #{inspect(other)}"}
  end

  defp do_validate(module, opts) do
    with :ok <- reject_reserved(opts),
         :ok <- module.validate(opts) do
      {:ok, {module, opts}}
    end
  end

  defp reject_reserved(opts) do
    case Keyword.take(opts, @reserved_keys) do
      [] ->
        :ok

      bad ->
        keys = bad |> Keyword.keys() |> inspect()

        {:error,
         "strategy options must not include #{keys}; those are plug-wide " <>
           "options, so set them outside the :strategy tuple instead"}
    end
  end

  @doc false

  @spec valid_header?(term()) :: boolean()

  def valid_header?(header) when is_binary(header) and header != "" do
    header == String.downcase(header)
  end

  def valid_header?(_), do: false

  @doc false

  @spec validate_optional_header(options()) :: :ok | {:error, String.t()}

  def validate_optional_header(opts) do
    case Keyword.get(opts, :header) do
      nil -> :ok
      header -> validate_header_format(header)
    end
  end

  @doc false

  @spec validate_required_header(options(), [binary()]) ::
          :ok | {:error, String.t()}

  def validate_required_header(opts, allowed) do
    case Keyword.get(opts, :header) do
      nil ->
        {:error, "requires a :header option of #{inspect(allowed)}"}

      header ->
        if header in allowed do
          :ok
        else
          with :ok <- validate_header_format(header) do
            {:error,
             ":header #{inspect(header)} must be one of #{inspect(allowed)}"}
          end
        end
    end
  end

  defp validate_header_format(header) do
    if valid_header?(header) do
      :ok
    else
      {:error,
       ":header must be a non-empty, lowercase string, got #{inspect(header)}"}
    end
  end

  defp header_names(opts) do
    case Keyword.get(opts, :header) do
      nil -> Keyword.get(opts, :headers, RemoteIp.Options.default(:headers))
      header -> [header]
    end
  end

  defp contains?(blocks, ip) do
    Enum.any?(blocks, &RemoteIp.Block.contains?(&1, ip))
  end
end
