CREATE TABLE IF NOT EXISTS "Organization" (
    "id"        TEXT PRIMARY KEY,
    "name"      TEXT NOT NULL,
    "slug"      TEXT NOT NULL UNIQUE,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "User" (
    "id"             TEXT PRIMARY KEY,
    "email"          TEXT NOT NULL UNIQUE,
    "password"       TEXT,
    "name"           TEXT,
    "avatarUrl"      TEXT,
    "role"           TEXT NOT NULL DEFAULT 'user',
    "provider"       TEXT NOT NULL DEFAULT 'local',
    "providerId"     TEXT,
    "emailVerified"  BOOLEAN NOT NULL DEFAULT false,
    "totpSecret"     TEXT,
    "totpEnabled"    BOOLEAN NOT NULL DEFAULT false,
    "organizationId" TEXT NOT NULL REFERENCES "Organization"("id"),
    "createdAt"      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt"      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "RefreshToken" (
    "id"        TEXT PRIMARY KEY,
    "userId"    TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
    "token"     TEXT NOT NULL UNIQUE,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "VerificationToken" (
    "id"        TEXT PRIMARY KEY,
    "userId"    TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE,
    "token"     TEXT NOT NULL UNIQUE,
    "purpose"   TEXT NOT NULL,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_RefreshToken_token ON "RefreshToken"("token");
CREATE INDEX IF NOT EXISTS idx_RefreshToken_userId ON "RefreshToken"("userId");
CREATE INDEX IF NOT EXISTS idx_VerificationToken_token ON "VerificationToken"("token");
CREATE INDEX IF NOT EXISTS idx_User_organizationId ON "User"("organizationId");
