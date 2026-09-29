defmodule RemoteIp.StrategiesTest do
  use ExUnit.Case, async: true

  doctest RemoteIp.Strategies.RightmostNonPrivate
  doctest RemoteIp.Strategies.LeftmostNonPrivate
  doctest RemoteIp.Strategies.RightmostTrustedCount
  doctest RemoteIp.Strategies.RightmostTrustedRange
  doctest RemoteIp.Strategies.SingleIpHeader
  doctest RemoteIp.Strategies.Chain

  alias RemoteIp.Strategies

  describe "RightmostNonPrivate" do
    test "returns the rightmost non-private, non-proxy IP" do
      head = [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}]
      opts = [header: "x-forwarded-for"]

      assert Strategies.RightmostNonPrivate.find(head, opts) == {1, 2, 3, 4}
    end

    test "falls back to the :headers option without :header" do
      head = [{"x-forwarded-for", "1.2.3.4, 2.3.4.5"}]
      opts = [headers: ~w[x-forwarded-for]]

      assert Strategies.RightmostNonPrivate.find(head, opts) == {2, 3, 4, 5}
    end
  end

  describe "LeftmostNonPrivate" do
    test "returns the leftmost non-private, non-proxy IP" do
      head = [{"x-forwarded-for", "10.0.0.1, 2.3.4.5"}]
      opts = [header: "x-forwarded-for"]

      assert Strategies.LeftmostNonPrivate.find(head, opts) == {2, 3, 4, 5}
    end
  end

  describe "RightmostTrustedCount" do
    test "returns the IP added by the first of count trusted proxies" do
      head = [{"x-forwarded-for", "1.2.3.4, 10.0.0.1, 10.0.0.2"}]
      opts = [header: "x-forwarded-for", count: 2]

      assert Strategies.RightmostTrustedCount.find(head, opts) == {10, 0, 0, 1}
    end

    test "returns nil when there are too few IPs" do
      head = [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}]
      opts = [header: "x-forwarded-for", count: 4]

      assert Strategies.RightmostTrustedCount.find(head, opts) == nil
    end
  end

  describe "RightmostTrustedRange" do
    test "skips trusted proxies, even with public IPs" do
      head = [{"x-forwarded-for", "1.1.1.1, 2.2.2.2, 103.21.244.1"}]
      opts = [header: "x-forwarded-for", proxies: [RemoteIp.Block.parse!("103.21.244.0/22")]]

      assert Strategies.RightmostTrustedRange.find(head, opts) == {2, 2, 2, 2}
    end

    test "does not auto-skip reserved IPs" do
      head = [{"x-forwarded-for", "1.2.3.4, 10.0.0.1"}]
      opts = [header: "x-forwarded-for"]

      assert Strategies.RightmostTrustedRange.find(head, opts) == {10, 0, 0, 1}
    end
  end

  describe "SingleIpHeader" do
    test "returns the last single-IP header value" do
      head = [{"x-real-ip", "1.2.3.4"}, {"x-real-ip", "5.6.7.8"}]
      opts = [header: "x-real-ip"]

      assert Strategies.SingleIpHeader.find(head, opts) == {5, 6, 7, 8}
    end

    test "does not treat the value as a comma-separated list" do
      head = [{"x-real-ip", "1.2.3.4, 5.6.7.8"}]
      opts = [header: "x-real-ip"]

      assert Strategies.SingleIpHeader.find(head, opts) == nil
    end
  end

  describe "Chain" do
    test "returns the first strategy's non-nil result" do
      opts = [
        strategies: [
          {Strategies.SingleIpHeader, header: "x-real-ip"},
          {Strategies.RightmostNonPrivate, header: "x-forwarded-for"}
        ]
      ]

      assert Strategies.Chain.find([{"x-real-ip", "1.2.3.4"}], opts) == {1, 2, 3, 4}
    end

    test "falls through when a strategy returns nil" do
      opts = [
        strategies: [
          {Strategies.SingleIpHeader, header: "x-real-ip"},
          {Strategies.RightmostNonPrivate, header: "x-forwarded-for"}
        ]
      ]

      assert Strategies.Chain.find([{"x-forwarded-for", "2.3.4.5"}], opts) == {2, 3, 4, 5}
    end
  end

  describe "RightmostTrustedCount validation" do
    test "requires :header" do
      assert {:error, msg} = Strategies.RightmostTrustedCount.validate([])
      assert msg =~ "requires a :header"
    end

    test "rejects headers other than x-forwarded-for/forwarded" do
      assert {:error, msg} = Strategies.RightmostTrustedCount.validate(header: "x-real-ip")
      assert msg =~ "must be one of"
    end

    test "accepts x-forwarded-for and forwarded" do
      assert Strategies.RightmostTrustedCount.validate(header: "x-forwarded-for") == :ok
      assert Strategies.RightmostTrustedCount.validate(header: "forwarded") == :ok
    end

    test "rejects a non-positive :count" do
      opts = [header: "forwarded", count: 0]
      assert {:error, msg} = Strategies.RightmostTrustedCount.validate(opts)
      assert msg =~ "positive integer"
      assert {:error, _} = Strategies.RightmostTrustedCount.validate(header: "forwarded", count: -1)
      assert {:error, _} = Strategies.RightmostTrustedCount.validate(header: "forwarded", count: "1")
    end

    test "defaults :count to 1" do
      assert Strategies.RightmostTrustedCount.validate(header: "forwarded") == :ok
    end
  end

  describe "RightmostTrustedCount positional parsing" do
    test "an obfuscated entry before the target position doesn't shift it" do
      head = [{"forwarded", "for=6.6.6.6, for=2.2.2.2, for=_hidden"}]
      opts = [header: "forwarded", count: 2]
      assert Strategies.RightmostTrustedCount.find(head, opts) == {2, 2, 2, 2}
    end

    test "an invalid entry at the target position returns nil rather than reindexing" do
      head = [{"forwarded", "for=6.6.6.6, for=_hidden, for=2.2.2.2"}]
      opts = [header: "forwarded", count: 2]
      assert Strategies.RightmostTrustedCount.find(head, opts) == nil
    end

    test "an ip:port entry (invalid for XFF) at the target position returns nil" do
      head = [{"x-forwarded-for", "6.6.6.6, 1.2.3.4:5678"}]
      opts = [header: "x-forwarded-for", count: 1]
      assert Strategies.RightmostTrustedCount.find(head, opts) == nil
    end
  end

  describe "RightmostTrustedRange validation" do
    test "requires :header" do
      assert {:error, msg} = Strategies.RightmostTrustedRange.validate([])
      assert msg =~ "requires a :header"
    end

    test "rejects headers other than x-forwarded-for/forwarded" do
      assert {:error, _} = Strategies.RightmostTrustedRange.validate(header: "x-client-ip")
    end
  end

  describe "RightmostTrustedRange positional parsing" do
    test "an invalid entry halts the scan instead of being skipped like a proxy" do
      head = [{"forwarded", "for=6.6.6.6, for=unknown, for=9.9.9.9"}]
      opts = [header: "forwarded", proxies: [RemoteIp.Block.parse!("9.9.9.9/32")]]
      assert Strategies.RightmostTrustedRange.find(head, opts) == nil
    end
  end

  describe "SingleIpHeader validation" do
    test "requires :header" do
      assert {:error, msg} = Strategies.SingleIpHeader.validate([])
      assert msg =~ "requires a :header"
    end

    test "rejects x-forwarded-for and forwarded" do
      assert {:error, msg} = Strategies.SingleIpHeader.validate(header: "x-forwarded-for")
      assert msg =~ "list header"
      assert {:error, _} = Strategies.SingleIpHeader.validate(header: "forwarded")
    end

    test "rejects an uppercase header" do
      assert {:error, msg} = Strategies.SingleIpHeader.validate(header: "X-Real-IP")
      assert msg =~ "lowercase"
    end

    test "accepts a valid single-ip header" do
      assert Strategies.SingleIpHeader.validate(header: "x-real-ip") == :ok
    end
  end

  describe "RightmostNonPrivate/LeftmostNonPrivate validation" do
    test "does not require :header" do
      assert Strategies.RightmostNonPrivate.validate([]) == :ok
      assert Strategies.LeftmostNonPrivate.validate([]) == :ok
    end

    test "still rejects an uppercase :header if given" do
      assert {:error, _} = Strategies.RightmostNonPrivate.validate(header: "X-Forwarded-For")
      assert {:error, _} = Strategies.LeftmostNonPrivate.validate(header: "X-Forwarded-For")
    end
  end

  describe "Chain validation" do
    test "requires a non-empty :strategies list" do
      assert {:error, _} = Strategies.Chain.validate([])
      assert {:error, _} = Strategies.Chain.validate(strategies: [])
      assert {:error, _} = Strategies.Chain.validate(strategies: "not a list")
    end

    test "validates every link, surfacing the first failure" do
      opts = [
        strategies: [
          Strategies.SingleIpHeader,
          {Strategies.RightmostTrustedCount, header: "x-forwarded-for"}
        ]
      ]

      assert {:error, msg} = Strategies.Chain.validate(opts)
      assert msg =~ "requires a :header"
    end

    test "rejects a bare nested Chain with no :strategies of its own" do
      opts = [strategies: [{Strategies.SingleIpHeader, header: "x-real-ip"}, Strategies.Chain]]
      assert {:error, _} = Strategies.Chain.validate(opts)
    end

    test "accepts a nested Chain that has its own :strategies" do
      inner = {Strategies.Chain, strategies: [{Strategies.SingleIpHeader, header: "x-client-ip"}]}
      opts = [strategies: [{Strategies.SingleIpHeader, header: "x-real-ip"}, inner]]
      assert Strategies.Chain.validate(opts) == :ok
    end

    test "rejects a link carrying plug-wide options" do
      opts = [
        strategies: [
          {Strategies.RightmostTrustedRange, header: "x-forwarded-for", proxies: ["1.2.3.0/24"]}
        ]
      ]

      assert {:error, msg} = Strategies.Chain.validate(opts)
      assert msg =~ "plug-wide"
    end
  end

  describe "Chain find/2" do
    test "a bare nested Chain with no :strategies of its own returns nil instead of hanging" do
      opts = [strategies: [{Strategies.SingleIpHeader, header: "x-real-ip"}, Strategies.Chain]]
      head = [{"x-real-ip", "bogus"}]
      task = Task.async(fn -> Strategies.Chain.find(head, opts) end)
      assert Task.yield(task, 200) == {:ok, nil}
    end
  end
end
