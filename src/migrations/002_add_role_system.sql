-- Migration: Add Role System with Multi-User Support
-- Phase 1.3 of ARCHITECTURE.md (revised)

-- Create installation_users join table for many-to-many with roles
CREATE TABLE IF NOT EXISTS public.installation_users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  installation_id UUID NOT NULL REFERENCES public.installations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'home_owner' CHECK (role IN ('home_owner', 'installer')),
  created_at TIMESTAMPTZ DEFAULT NOW(),

  -- Each user can only have one role per installation
  UNIQUE(installation_id, user_id)
);

-- Add global admin flag to users table (for platform admins like Tomer)
ALTER TABLE public.users
ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_installation_users_installation ON public.installation_users(installation_id);
CREATE INDEX IF NOT EXISTS idx_installation_users_user ON public.installation_users(user_id);
CREATE INDEX IF NOT EXISTS idx_installation_users_role ON public.installation_users(role);
CREATE INDEX IF NOT EXISTS idx_users_is_admin ON public.users(is_admin) WHERE is_admin = TRUE;

-- Migrate existing claimed_by relationships to installation_users
-- (existing owners become home_owner role)
INSERT INTO public.installation_users (installation_id, user_id, role)
SELECT id, claimed_by, 'home_owner'
FROM public.installations
WHERE claimed_by IS NOT NULL
ON CONFLICT (installation_id, user_id) DO NOTHING;

-- Remove the role column from installations (no longer needed there)
ALTER TABLE public.installations DROP COLUMN IF EXISTS role;
