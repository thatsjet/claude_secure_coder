# Synthetic vulnerable Python file — used by run-tests.sh.
# DO NOT CONNECT THIS TO A REAL DATABASE OR RUN IT IN PRODUCTION.

import os
import pickle
import subprocess

# Hardcoded Anthropic API key — should hard-block via VulnPatternHook.
ANTHROPIC_API_KEY = "sk-ant-api03-FAKEKEY1234567890123456789012345678901234567890aB"

# AWS access key — should hard-block via VulnPatternHook.
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# Database URL with embedded password — should hard-block via VulnPatternHook.
DATABASE_URL = "postgres://admin:hunter2@db.example.com:5432/app"

def deserialize_user_input(blob: bytes):
    # pickle.loads on untrusted data — should advisory via VulnPatternHook.
    return pickle.loads(blob)

def shell_user(input_str: str):
    # subprocess shell=True with user input — should advisory via VulnPatternHook.
    return subprocess.run(input_str, shell=True, check=True)

def evaluate(expr: str):
    # eval on user input — should advisory.
    return eval(expr)

def hash_password(password: str) -> str:
    # MD5 password hashing — should advisory (weak crypto).
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()

def random_token() -> int:
    # random.random() in token context — should advisory (weak crypto).
    import random
    token = random.random()
    return token
