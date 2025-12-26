-- Migration: Add Role System to Installations
-- Phase 1.3 of ARCHITECTURE.md

-- Add role column with CHECK constraint
-- Valid roles: 'home_owner', 'installer', 'admin'
ALTER TABLE public.installations
ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'home_owner';

-- Add CHECK constraint for valid roles
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'installations_role_check'
  ) THEN
    ALTER TABLE public.installations
    ADD CONSTRAINT installations_role_check
    CHECK (role IN ('home_owner', 'installer', 'admin'));
  END IF;
END $$;

-- Create index for role queries
CREATE INDEX IF NOT EXISTS idx_installations_role ON public.installations(role);

-- Update existing installations to have home_owner role (if NULL)
UPDATE public.installations SET role = 'home_owner' WHERE role IS NULL;
