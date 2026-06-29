#!/usr/bin/env python3
"""Generate an RS256 signing key for the Control Plane."""
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Installing cryptography...")
    os.system(f"{sys.executable} -m pip install cryptography")
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization


def main():
    key_dir = Path("control-plane/keys")
    key_dir.mkdir(parents=True, exist_ok=True)
    key_path = key_dir / "signing.pem"

    if key_path.exists():
        print(f"Key already exists at {key_path}")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    os.chmod(key_path, 0o600)
    print(f"Generated RS256 key at {key_path}")


if __name__ == "__main__":
    main()
