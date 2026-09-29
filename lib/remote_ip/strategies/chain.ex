defmodule RemoteIp.Strategies.Chain do
  @behaviour RemoteIp.Strategy

  @moduledoc """
  Tries a list of strategies in order, returning the first non-`nil` result.

  Each strategy is given as a `{module, options}` tuple or a bare module. The
  options of each link are merged over the options given to the chain, so the
  global options (such as `:proxies`, `:clients`, and `:parsers`) are shared -
  but `:strategies` itself is never passed down, so a link that is itself a
  bare `Chain` must specify its own `:strategies`.

  ## Options

    * `:strategies` - required; a non-empty list of strategy specs to try, in
      order. Each one is validated the same way the top-level `:strategy`
      option is (see `RemoteIp.Strategy.validate_spec/1`).

  ## Examples

      iex> opts = [
      ...>   strategies: [
      ...>     {RemoteIp.Strategies.SingleIpHeader, header: "x-real-ip"},
      ...>     {RemoteIp.Strategies.RightmostNonPrivate, header: "x-forwarded-for"}
      ...>   ]
      ...> ]
      iex> RemoteIp.Strategies.Chain.find([{"x-forwarded-for", "2.3.4.5"}], opts)
      {2, 3, 4, 5}
  """

  @impl RemoteIp.Strategy

  def find(headers, opts) do
    strategies = Keyword.get(opts, :strategies, [])
    base_opts = Keyword.delete(opts, :strategies)

    Enum.find_value(strategies, fn spec ->
      {module, strategy_opts} = RemoteIp.Strategy.normalize_spec(spec)
      module.find(headers, Keyword.merge(base_opts, strategy_opts))
    end)
  end

  @impl RemoteIp.Strategy

  def validate(opts) do
    case Keyword.get(opts, :strategies) do
      strategies when is_list(strategies) and strategies != [] ->
        validate_each(strategies)

      [] ->
        {:error, "the :strategies option must not be empty"}

      _ ->
        {:error,
         "the :strategies option must be a non-empty list of strategies"}
    end
  end

  defp validate_each(strategies) do
    Enum.find_value(strategies, :ok, fn spec ->
      case RemoteIp.Strategy.validate_spec(spec) do
        {:ok, _} -> nil
        {:error, _} = error -> error
      end
    end)
  end
end
