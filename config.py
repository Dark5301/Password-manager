"""
Configuration constants for the credentials manager.
"""

import os
from typing import Dict, Any

# Database Configuration
DATABASE_PATH = "credentials.db"  # or use :memory: for testing

# KDF Parameters for Argon2id
KDF_PARAMS: Dict[str, Any] = {
    "time_cost": 3,           # Number of iterations
    "memory_cost": 64 * 1024, # 64MB in KB (64 * 1024)
    "parallelism": 4,         # Number of parallel threads
    "hash_len": 32,           # Output key length (32 bytes = 256 bits)
    "salt_len": 16,           # Salt length in bytes
}

# Cryptography Constants
NONCE_SIZE = 24               # XChaCha20-Poly1305 uses 24-byte nonces
SALT_SIZE = 16                # Argon2 salt size
KEY_SIZE = 32                 # ChaCha20 key size (32 bytes = 256 bits)

# Security Settings
MIN_MASTER_PASSWORD_LENGTH = 8
MAX_CREDENTIAL_NAME_LENGTH = 255

# Application Settings
CREDENTIAL_METADATA_KEYS = ['url', 'notes', 'category', 'tags']  # Optional metadata fields

# Serialization Settings
SERIALIZATION_FORMAT = "cbor"  # Options: "cbor" or "json"

def validate_config() -> None:
    """
    Validate that all configuration values are sane and secure.
    This runs when the module is imported to catch configuration errors early.
    """
    # KDF validation
    assert KDF_PARAMS["time_cost"] >= 2, "Time cost too low (min 2)"
    assert KDF_PARAMS["memory_cost"] >= 16 * 1024, "Memory cost too low (min 16MB)"
    assert KDF_PARAMS["parallelism"] >= 1, "Parallelism must be at least 1"
    assert KDF_PARAMS["hash_len"] in [16, 24, 32], "Hash length must be 16, 24, or 32 bytes"
    assert KDF_PARAMS["salt_len"] >= 8, "Salt too short (min 8 bytes)"
    
    # Cryptography validation
    assert NONCE_SIZE == 24, "XChaCha20-Poly1305 requires 24-byte nonces"
    assert SALT_SIZE >= 16, "Salt should be at least 16 bytes for security"
    assert KEY_SIZE == 32, "ChaCha20-Poly1305 requires 32-byte (256-bit) keys"
    
    # Security validation
    assert MIN_MASTER_PASSWORD_LENGTH >= 8, "Master password minimum length too weak"
    assert MAX_CREDENTIAL_NAME_LENGTH > 0, "Credential name max length invalid"
    
    # Application validation
    assert SERIALIZATION_FORMAT in ["cbor", "json"], "Serialization format must be 'cbor' or 'json'"
    
    print("✓ Configuration validated successfully")

def get_database_path() -> str:
    """
    Get the database path, creating directory if needed.
    """
    if DATABASE_PATH != ":memory:":
        directory = os.path.dirname(DATABASE_PATH)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, mode=0o700)  # Secure directory permissions
    return DATABASE_PATH

def is_test_environment() -> bool:
    """
    Check if we're running in a test environment.
    Useful for using in-memory databases or faster KDF settings.
    """
    return os.getenv('CREDENTIALS_TEST_ENV') == '1'

# Environment-specific overrides
if is_test_environment():
    # Faster settings for testing
    KDF_PARAMS["time_cost"] = 1
    KDF_PARAMS["memory_cost"] = 16 * 1024  # 16MB for tests
    DATABASE_PATH = ":memory:"
    print("⚠ Running in test environment with faster KDF settings")

# Validate configuration on import
try:
    validate_config()
except AssertionError as e:
    print(f"❌ Configuration error: {e}")
    raise
