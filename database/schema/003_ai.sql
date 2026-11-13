BEGIN;
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS ai_chunks (
    chunk_key          TEXT PRIMARY KEY,
    server_id          BIGINT REFERENCES servers (server_id) ON DELETE CASCADE,
    server_version_id  BIGINT REFERENCES server_versions (server_version_id) ON DELETE CASCADE,
    kind               TEXT NOT NULL CHECK (kind IN ('server', 'finding', 'methodology')),
    title              TEXT NOT NULL,
    content            TEXT NOT NULL,
    source_url         TEXT,
    observed_at        TIMESTAMPTZ,
    content_hash       TEXT NOT NULL,
    embedding_model    TEXT NOT NULL,
    embedding          vector(512) NOT NULL,
    search_vector      TSVECTOR GENERATED ALWAYS AS (to_tsvector('english', title || ' ' || content)) STORED,
    indexed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_run           UUID NOT NULL
);
CREATE INDEX IF NOT EXISTS ai_chunks_embedding_idx ON ai_chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS ai_chunks_search_idx ON ai_chunks USING gin (search_vector);
CREATE INDEX IF NOT EXISTS ai_chunks_version_idx ON ai_chunks (server_version_id);
INSERT INTO schema_migrations (version) VALUES ('003_ai') ON CONFLICT DO NOTHING;
COMMIT;
