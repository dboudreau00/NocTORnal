"""IAM: users, MFA credentials, RBAC (role/permission), ABAC
(case_assignment), break-glass, dual control, server-side sessions."""
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = iam, core, public;

CREATE TABLE app_user (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           citext UNIQUE NOT NULL,
  display_name    text NOT NULL,
  password_hash   text,                    -- argon2id
  is_active       boolean NOT NULL DEFAULT true,
  -- Clearance ceiling. A user can never see above this, whatever their
  -- case assignment says.
  tlp_clearance   tlp NOT NULL DEFAULT 'GREEN',
  compartments    text[] NOT NULL DEFAULT '{}',
  -- MFA. TOTP as the floor, WebAuthn preferred.
  totp_secret_ciphertext bytea,
  totp_key_id     text,
  totp_enrolled_at timestamptz,
  mfa_required    boolean NOT NULL DEFAULT true,
  recovery_codes_hash text[],
  failed_logins   int NOT NULL DEFAULT 0,
  locked_until    timestamptz,
  last_login_at   timestamptz,
  password_changed_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  deactivated_at  timestamptz
);

CREATE TABLE webauthn_credential (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  credential_id  bytea UNIQUE NOT NULL,
  public_key     bytea NOT NULL,
  sign_count     bigint NOT NULL DEFAULT 0,
  aaguid         uuid,
  transports     text[],
  nickname       text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_used_at   timestamptz
);

CREATE TABLE role (
  key         text PRIMARY KEY,
  display_name text NOT NULL,
  description text,
  is_system   boolean NOT NULL DEFAULT false
);

CREATE TABLE permission (
  key         text PRIMARY KEY,            -- 'case.read','graph.merge','evidence.export'
  description text NOT NULL,
  -- Ops that demand a fresh MFA challenge regardless of session age.
  requires_step_up boolean NOT NULL DEFAULT false,
  -- Ops that need a second authoriser.
  requires_dual_control boolean NOT NULL DEFAULT false
);

CREATE TABLE role_permission (
  role_key       text NOT NULL REFERENCES role(key) ON DELETE CASCADE,
  permission_key text NOT NULL REFERENCES permission(key) ON DELETE CASCADE,
  PRIMARY KEY (role_key, permission_key)
);

CREATE TABLE user_role (
  user_id  uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  role_key text NOT NULL REFERENCES role(key),
  PRIMARY KEY (user_id, role_key)
);

-- ABAC layer: role grants the verb, assignment grants the row.
CREATE TABLE case_assignment (
  case_id     uuid NOT NULL REFERENCES "case"(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  role_key    text NOT NULL REFERENCES role(key),
  granted_by  uuid NOT NULL,
  granted_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz,                 -- time-boxed access by default
  PRIMARY KEY (case_id, user_id)
);
-- now() is STABLE, not IMMUTABLE, so "currently active" cannot live in a
-- partial-index predicate; index both columns and filter at query time.
CREATE INDEX ON case_assignment (user_id, expires_at);

-- Emergency access. Always allowed, always loud.
CREATE TABLE break_glass (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES app_user(id),
  case_id      uuid REFERENCES "case"(id),
  justification text NOT NULL,
  started_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  reviewed_by  uuid,
  reviewed_at  timestamptz,
  review_outcome text
);

CREATE TABLE dual_control_request (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action        text NOT NULL,
  payload       jsonb NOT NULL,
  requested_by  uuid NOT NULL REFERENCES app_user(id),
  requested_at  timestamptz NOT NULL DEFAULT now(),
  approved_by   uuid REFERENCES app_user(id),
  approved_at   timestamptz,
  executed_at   timestamptz,
  state         text NOT NULL DEFAULT 'PENDING',
  CONSTRAINT dual_control_distinct CHECK (approved_by IS NULL OR approved_by <> requested_by)
);

CREATE TABLE session (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  token_hash    bytea NOT NULL UNIQUE,
  issued_at     timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  last_seen_at  timestamptz,
  ip_hash       bytea,                     -- hashed, not stored raw
  user_agent    text,
  mfa_satisfied_at timestamptz,            -- step-up freshness clock
  revoked_at    timestamptz,
  revoke_reason text
);
CREATE INDEX ON session (user_id) WHERE revoked_at IS NULL;
""")


def downgrade() -> None:
    run("""
DROP TABLE iam.session;
DROP TABLE iam.dual_control_request;
DROP TABLE iam.break_glass;
DROP TABLE iam.case_assignment;
DROP TABLE iam.user_role;
DROP TABLE iam.role_permission;
DROP TABLE iam.permission;
DROP TABLE iam.role;
DROP TABLE iam.webauthn_credential;
DROP TABLE iam.app_user;
""")
