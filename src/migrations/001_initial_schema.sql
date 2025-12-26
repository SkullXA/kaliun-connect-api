-- Kaliun Connect API Database Schema (Simplified - no auth schema dependency)
-- Run this in pgAdmin Query Tool

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (standalone, no auth.users dependency)
CREATE TABLE IF NOT EXISTS public.users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  name TEXT,
  provider TEXT DEFAULT 'email',
  provider_id TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Installations table
CREATE TABLE IF NOT EXISTS public.installations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  install_id TEXT UNIQUE NOT NULL,
  hostname TEXT DEFAULT 'kaliunbox',
  architecture TEXT,
  nixos_version TEXT,
  claim_code TEXT UNIQUE NOT NULL,

  -- Ownership & Role
  claimed_by UUID REFERENCES public.users(id),
  claimed_at TIMESTAMPTZ,
  role TEXT DEFAULT 'home_owner' CHECK (role IN ('home_owner', 'installer', 'admin')),

  -- Customer info
  customer_name TEXT,
  customer_email TEXT,
  customer_address TEXT,
  
  -- Tokens
  access_token TEXT,
  refresh_token TEXT,
  access_expires_at TIMESTAMPTZ,
  refresh_expires_at TIMESTAMPTZ,
  config_confirmed BOOLEAN DEFAULT FALSE,
  
  -- Pangolin/Remote Access
  pangolin_site_id TEXT,
  pangolin_newt_id TEXT,
  pangolin_newt_secret TEXT,
  pangolin_endpoint TEXT,
  pangolin_url TEXT,
  
  -- Health
  last_health_at TIMESTAMPTZ,
  last_health JSONB,
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Health reports table
CREATE TABLE IF NOT EXISTS public.health_reports (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installation_id UUID REFERENCES public.installations(id) ON DELETE CASCADE,
  data JSONB NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Logs table
CREATE TABLE IF NOT EXISTS public.logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installation_id UUID REFERENCES public.installations(id) ON DELETE CASCADE,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  service TEXT,
  level TEXT DEFAULT 'info',
  message TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sessions table
CREATE TABLE IF NOT EXISTS public.sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES public.users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_installations_install_id ON public.installations(install_id);
CREATE INDEX IF NOT EXISTS idx_installations_claim_code ON public.installations(claim_code);
CREATE INDEX IF NOT EXISTS idx_installations_claimed_by ON public.installations(claimed_by);
CREATE INDEX IF NOT EXISTS idx_installations_role ON public.installations(role);
CREATE INDEX IF NOT EXISTS idx_health_reports_installation_id ON public.health_reports(installation_id);
CREATE INDEX IF NOT EXISTS idx_logs_installation_id ON public.logs(installation_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON public.sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON public.sessions(user_id);
