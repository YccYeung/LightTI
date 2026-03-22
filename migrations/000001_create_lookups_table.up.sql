CREATE TABLE lookups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ioc varchar(200) NOT NULL,
  ioc_type varchar(20) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);