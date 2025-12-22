defmodule JwsDemoWeb.RateLimitPlug do
  @moduledoc """
  Simple token bucket rate limiter for public endpoints.

  Protects endpoints like JWKS from DoS attacks by limiting requests per IP.

  ## Implementation

  Uses ETS table to track token buckets per IP:
  - Each IP gets a bucket with max tokens
  - Tokens refill over time (1 token per refill_interval)
  - Request consumes 1 token
  - Returns 429 Too Many Requests when bucket empty

  ## Configuration

  - `:max_requests` - Max requests in time window (default: 100)
  - `:window_seconds` - Time window in seconds (default: 60)

  ## Examples

      # In router.ex
      pipeline :jwks_public do
        plug :accepts, ["json"]
        plug JwsDemoWeb.RateLimitPlug, max_requests: 10, window_seconds: 60
      end

      scope "/.well-known", JwsDemoWeb do
        pipe_through :jwks_public
        get "/jwks.json", JWKSController, :index
      end

  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @table_name :rate_limit_buckets
  @default_max_requests 100
  @default_window_seconds 60

  @impl true
  def init(opts) do
    # Ensure ETS table exists
    case :ets.whereis(@table_name) do
      :undefined ->
        :ets.new(@table_name, [:set, :public, :named_table, read_concurrency: true])

      _ref ->
        :ok
    end

    %{
      max_requests: Keyword.get(opts, :max_requests, @default_max_requests),
      window_seconds: Keyword.get(opts, :window_seconds, @default_window_seconds)
    }
  end

  @impl true
  def call(conn, opts) do
    ip = get_client_ip(conn)
    now = System.system_time(:second)

    case check_rate_limit(ip, now, opts) do
      :ok ->
        conn

      {:error, :rate_limited} ->
        Logger.warning("Rate limit exceeded for IP: #{inspect(ip)}")

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(429, Jason.encode!(%{
          error: "rate_limit_exceeded",
          message: "Too many requests. Please try again later.",
          retry_after: opts.window_seconds
        }))
        |> halt()
    end
  end

  # Private functions

  defp get_client_ip(conn) do
    # Get forwarded IP if behind proxy, otherwise remote_ip
    case get_req_header(conn, "x-forwarded-for") do
      [forwarded | _] ->
        # Take first IP from X-Forwarded-For chain
        forwarded
        |> String.split(",")
        |> List.first()
        |> String.trim()

      [] ->
        # Use remote_ip from conn
        conn.remote_ip
        |> :inet.ntoa()
        |> to_string()
    end
  end

  defp check_rate_limit(ip, now, opts) do
    bucket_key = {:bucket, ip}

    # Get or initialize bucket
    {tokens, last_refill} =
      case :ets.lookup(@table_name, bucket_key) do
        [{^bucket_key, tokens, last_refill}] ->
          # Refill tokens based on time elapsed
          elapsed = now - last_refill
          refill_rate = opts.max_requests / opts.window_seconds
          new_tokens = min(opts.max_requests, tokens + elapsed * refill_rate)
          {new_tokens, now}

        [] ->
          # New bucket, start with max tokens
          {opts.max_requests, now}
      end

    # Check if we have tokens available
    if tokens >= 1 do
      # Consume 1 token
      :ets.insert(@table_name, {bucket_key, tokens - 1, last_refill})
      :ok
    else
      # Rate limited
      {:error, :rate_limited}
    end
  end
end
