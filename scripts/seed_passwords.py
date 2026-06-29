#!/usr/bin/env python3
"""Emit bcrypt-hashed secrets to .env for the demo users, clients, and roles."""
import os
import sys
from pathlib import Path

try:
    import bcrypt
except ImportError:
    print("Installing bcrypt...")
    os.system(f"{sys.executable} -m pip install bcrypt")
    import bcrypt


def hash_pw(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=10)).decode()


def main():
    env_path = Path(".env")
    if not env_path.exists():
        print("Copy .env.example to .env first.")
        sys.exit(1)

    # Hash the canonical demo values
    user_123_hash = hash_pw("pw123")
    user_456_hash = hash_pw("pw123")
    user_789_hash = hash_pw("pw123")
    web_app_hash = hash_pw("web_app_client_secret_change_me")
    copilot_hash = hash_pw("agent_copilot_secret_change_me")
    etl_hash = hash_pw("agent_etl_secret_change_me")

    print("Hashed secrets (paste into init.sql):")
    print()
    print(f"  user_123:        {user_123_hash}")
    print(f"  user_456:        {user_456_hash}")
    print(f"  user_789:        {user_789_hash}")
    print(f"  web-app:         {web_app_hash}")
    print(f"  agent_copilot:   {copilot_hash}")
    print(f"  agent_etl:       {etl_hash}")
    print()
    print("Also place a copy of these as hashed_client_secrets in init.sql.")


if __name__ == "__main__":
    main()
