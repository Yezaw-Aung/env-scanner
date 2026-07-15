"""
Sample project #1 — Python backend with hardcoded secrets.

Contains:
  - A JWT signing secret (caught by variable-name pattern)
  - A PostgreSQL connection string with password (caught by entropy)
  - A dummy connection string (should NOT be flagged — localhost URL)
"""

import os

# Bug: JWT secret hardcoded in source
JWT_SECRET = "jwt_signing_secret_key_1234567890_abcdefg_XYZ_!!!!"

# Bug: database URL with password committed
DATABASE_URL = "postgresql://db_admin:admin_P@ssw0rd_987654321@prod-db.cluster.internal:5432/production"

# This is fine — local development URL, no real credentials
LOCAL_DEV_URL = "http://localhost:5432/local"

def get_connection():
    print(f"Connecting to: {DATABASE_URL}")
