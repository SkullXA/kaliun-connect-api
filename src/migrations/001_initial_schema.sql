-- Kaliun Connect API Database Schema
-- Run this in Supabase Studio SQL Editor

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table (extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  name TEXT,
  email TEXT UNIQUE NOT NULL,
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
  
  -- Ownership
  claimed_by UUID REFERENCES public.profiles(id),
  claimed_at TIMESTAMPTZ,
  
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

-- Device codes for OAuth
CREATE TABLE IF NOT EXISTS public.device_codes (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  device_code TEXT UNIQUE NOT NULL,
  user_code TEXT UNIQUE NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT DEFAULT 'profile',
  user_id UUID REFERENCES public.profiles(id),
  authorized BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Sessions (for web UI)
CREATE TABLE IF NOT EXISTS public.sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES public.profiles(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_installations_install_id ON public.installations(install_id);
CREATE INDEX IF NOT EXISTS idx_installations_claim_code ON public.installations(claim_code);
CREATE INDEX IF NOT EXISTS idx_installations_claimed_by ON public.installations(claimed_by);
CREATE INDEX IF NOT EXISTS idx_health_reports_installation_id ON public.health_reports(installation_id);
CREATE INDEX IF NOT EXISTS idx_logs_installation_id ON public.logs(installation_id);
CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON public.device_codes(user_code);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON public.sessions(token);

-- Row Level Security (RLS) Policies
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.health_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.logs ENABLE ROW LEVEL SECURITY;

-- Profiles: Users can only see/edit their own profile
CREATE POLICY "Users can view own profile" ON public.profiles
  FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile" ON public.profiles
  FOR UPDATE USING (auth.uid() = id);

-- Installations: Users can only see their own installations
CREATE POLICY "Users can view own installations" ON public.installations
  FOR SELECT USING (claimed_by = auth.uid());
CREATE POLICY "Service role can manage all installations" ON public.installations
  FOR ALL USING (true);

-- Health reports: Users can view their installations' health
CREATE POLICY "Users can view own installation health" ON public.health_reports
  FOR SELECT USING (
    installation_id IN (
      SELECT id FROM public.installations WHERE claimed_by = auth.uid()
    )
  );

-- Logs: Users can view their installations' logs
CREATE POLICY "Users can view own installation logs" ON public.logs
  FOR SELECT USING (
    installation_id IN (
      SELECT id FROM public.installations WHERE claimed_by = auth.uid()
    )
  );

-- Function to auto-create profile on signup
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, name)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'name', NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1))
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to create profile on auth signup
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for updated_at
CREATE TRIGGER update_profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TRIGGER update_installations_updated_at
  BEFORE UPDATE ON public.installations
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- Clean up expired device codes (run periodically)
CREATE OR REPLACE FUNCTION public.cleanup_expired_device_codes()
RETURNS void AS $$
BEGIN
  DELETE FROM public.device_codes WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Clean up old health reports (keep last 100 per installation)
CREATE OR REPLACE FUNCTION public.cleanup_old_health_reports()
RETURNS void AS $$
BEGIN
  DELETE FROM public.health_reports
  WHERE id NOT IN (
    SELECT id FROM (
      SELECT id, ROW_NUMBER() OVER (PARTITION BY installation_id ORDER BY created_at DESC) as rn
      FROM public.health_reports
    ) t WHERE rn <= 100
  );
END;
$$ LANGUAGE plpgsql;

-- Clean up old logs (keep last 500 per installation)
CREATE OR REPLACE FUNCTION public.cleanup_old_logs()
RETURNS void AS $$
BEGIN
  DELETE FROM public.logs
  WHERE id NOT IN (
    SELECT id FROM (
      SELECT id, ROW_NUMBER() OVER (PARTITION BY installation_id ORDER BY created_at DESC) as rn
      FROM public.logs
    ) t WHERE rn <= 500
  );
END;
$$ LANGUAGE plpgsql;

-- Grant permissions
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;

