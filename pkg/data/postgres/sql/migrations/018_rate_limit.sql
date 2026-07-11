-- Durable, instance-independent rate limiting.
--
-- POST /auth/login mints a login-token row and (in prod) sends an email on
-- every hit, and token issuance is otherwise unbounded — both are abusable, and
-- an in-memory limiter resets on deploy and doesn't coordinate across Cloud Run
-- instances. This fixed-window counter lives in Postgres so limits survive
-- scaling and restarts.
--
-- One row per (key, window_start). A request buckets its timestamp to the start
-- of its window and UPSERTs count = count + 1; the limiter reads the post-
-- increment count and rejects when it exceeds the limit. Keys are namespaced by
-- caller code, e.g. "login-email:<normalized-email>", "login-ip:<ip>",
-- "token-issue:<tenant-id>". Old windows are pruned opportunistically (see
-- PruneRateEvents) — no background job required. Idempotent.
CREATE TABLE IF NOT EXISTS devradar_rate_event (
    bucket_key   TEXT NOT NULL,          -- caller-namespaced identity
    window_start TIMESTAMPTZ NOT NULL,   -- floor(now()/window)*window
    count        INT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_key, window_start)
);

-- Sweep old windows cheaply (the limiter calls this occasionally). An index on
-- window_start keeps the prune a range scan rather than a full table scan.
CREATE INDEX IF NOT EXISTS idx_devradar_rate_event_window
    ON devradar_rate_event (window_start);
