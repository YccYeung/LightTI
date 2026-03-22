CREATE TABLE enrichment_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  lookup_id UUID NOT NULL REFERENCES lookups (id),
  source varchar(50) NOT NULL,
  result JSONB NOT NULL,
  error TEXT,  
  created_at TIMESTAMPTZ DEFAULT NOW()
);