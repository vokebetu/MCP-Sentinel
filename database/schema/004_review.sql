BEGIN;
DROP INDEX IF EXISTS ai_chunks_embedding_idx;
ALTER TABLE ai_chunks ALTER COLUMN embedding TYPE halfvec(512) USING embedding::halfvec(512);
CREATE INDEX ai_chunks_embedding_idx ON ai_chunks USING hnsw (embedding halfvec_cosine_ops);

CREATE VIEW tool_review_flags AS
SELECT t.tool_observation_id, t.server_version_id, t.tool_name, f.flag, f.explanation,
       substring(regexp_replace(t.description, '\s+', ' ', 'g') from '(?i)(.{0,60}(?:' || f.pattern || ').{0,60})') AS matched_text
FROM tool_observations t
JOIN (VALUES
    ('hidden_instruction', 'Tells the model to ignore instructions or to hide actions from the user.',
     'ignore (all |any |the )?(previous|prior|above|earlier|other) (instructions|prompts|rules)|disregard (all |any |the )?(previous|prior|above) |<\s*/?\s*(important|system|instructions?|secret)\s*>|do not (tell|inform|mention|reveal|show|notify)[^.]{0,40}user|without (telling|informing|notifying|asking) the user|hide (this|it) from the user'),
    ('invisible_characters', 'Contains zero-width or text-direction characters that can hide text.',
     '[​-‏‪-‮⁠-⁤﻿]'),
    ('sensitive_reference', 'Mentions private keys, SSH keys, credential files or agent configuration files.',
     '~/\.ssh|\mid_rsa\M|\.ssh/|/etc/passwd|/etc/shadow|\.aws/credentials|claude_desktop_config|mcp\.json|private[ _-]key'),
    ('tool_redirect', 'Tells the model to call this tool before or instead of other tools.',
     'instead of (using|calling) (any|the|other) tools?|before (using|calling) any other tool|always (call|use|invoke|run) this tool (first|before)|must (call|use|invoke) this tool (first|before)')
) AS f(flag, explanation, pattern) ON t.description ~* f.pattern;

INSERT INTO schema_migrations (version) VALUES ('004_review') ON CONFLICT DO NOTHING;
COMMIT;
