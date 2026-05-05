# Synthetic SAFE Python file — should produce zero findings.

import os
import secrets
import subprocess
import hashlib
from argon2 import PasswordHasher

# Secrets via env — no literal.
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]

def deserialize_user_input(blob: str):
    # JSON instead of pickle.
    import json
    return json.loads(blob)

def list_files(directory: str):
    # Array-form subprocess.
    return subprocess.run(["ls", "-la", directory], check=True, capture_output=True)

def hash_password(password: str) -> str:
    # Argon2id, not MD5.
    return PasswordHasher().hash(password)

def random_token() -> str:
    # secrets.token_urlsafe — cryptographic source.
    return secrets.token_urlsafe(32)
