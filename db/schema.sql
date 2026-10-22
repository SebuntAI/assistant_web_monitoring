-- Apply as the assistant_web_monitoring PostgreSQL role.
-- JSONL remains the short-term operational log. These tables keep structured
-- event metadata and local Ollama analyses for longer-term retrieval.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS public.web_activity_events (
    event_id    TEXT PRIMARY KEY,
    event_time  TIMESTAMPTZ,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    host        TEXT,
    details     JSONB NOT NULL,
    stored_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS web_activity_events_time_idx
    ON public.web_activity_events (event_time DESC);

CREATE INDEX IF NOT EXISTS web_activity_events_host_idx
    ON public.web_activity_events (host);

CREATE TABLE IF NOT EXISTS public.web_activity_analyses (
    analysis_id BIGSERIAL PRIMARY KEY,
    analyzed_at TIMESTAMPTZ NOT NULL,
    model       TEXT NOT NULL,
    event_ids   TEXT[] NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('complete', 'error')),
    summary     TEXT,
    activities  JSONB,
    error       TEXT,
    result      JSONB NOT NULL,
    stored_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS web_activity_analyses_time_idx
    ON public.web_activity_analyses (analyzed_at DESC);

CREATE TABLE IF NOT EXISTS public.web_activity_content_chunks (
    content_chunk_id BIGSERIAL PRIMARY KEY,
    event_id         TEXT NOT NULL REFERENCES public.web_activity_events(event_id) ON DELETE CASCADE,
    chunk_index      INTEGER NOT NULL,
    content_kind     TEXT NOT NULL,
    content_type     TEXT,
    content_text     TEXT NOT NULL,
    content_sha256   TEXT,
    content_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    request_headers  JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    embedding        vector(768),
    embedding_model  TEXT,
    stored_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (event_id, chunk_index)
);

CREATE INDEX IF NOT EXISTS web_activity_content_event_idx
    ON public.web_activity_content_chunks (event_id);
CREATE INDEX IF NOT EXISTS web_activity_content_embedding_idx
    ON public.web_activity_content_chunks USING hnsw (embedding vector_cosine_ops);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON ALL TABLES IN SCHEMA public TO human;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO assistant;
GRANT USAGE, SELECT, UPDATE
    ON ALL SEQUENCES IN SCHEMA public TO human;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO human;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO assistant;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO human;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO assistant_web_monitoring;
