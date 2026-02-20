-- Create session_models table
CREATE TABLE IF NOT EXISTS session_models (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    provider_id VARCHAR(255),
    model_id VARCHAR(255),
    agent_state VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE,
    last_modified TIMESTAMP WITH TIME ZONE
);

-- Create message_models table
CREATE TABLE IF NOT EXISTS message_models (
    id VARCHAR(255) PRIMARY KEY,
    session_id VARCHAR(255) REFERENCES session_models(id) ON DELETE CASCADE,
    source VARCHAR(50),
    type VARCHAR(50),
    payload BYTEA,
    timestamp TIMESTAMP WITH TIME ZONE,
    metadata JSONB
);
