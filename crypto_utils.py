# crypto_utils.py
from config import KDF_PARAMS
from argon2.low_level import hash_secret_raw, Type
import os
from config import SALT_SIZE
from models import KDFHeader
import json
from nacl import bindings
from config import NONCE_SIZE

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive an encryption key from a master password using Argon2id.
    
    Args:
        master_password: The user's master password
        salt: Random salt (should be 16 bytes)
    
    Returns:
        32-byte encryption key
    """
    # Step 1: Convert password to bytes
    password_bytes = master_password.encode('utf-8')
    
    # Step 2: Use hash_secret_raw
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=KDF_PARAMS["time_cost"],
        memory_cost=KDF_PARAMS["memory_cost"],
        parallelism=KDF_PARAMS["parallelism"],
        hash_len=KDF_PARAMS["hash_len"],
        type=Type.ID
    )
    
    # Step 3: Return the key
    return key

def generate_kdf_header() -> KDFHeader:
	"""
	Generate a new KDF header with a random salt. 

	This should be called ONCE when creating a new vault.
	The returned KDFHeader should be saved to the database.

	Returns:
		KDFHeader object with random salt and KDF parameters
	"""
	# Step 1: Generate random salt 
	salt = os.urandom(SALT_SIZE)

	# Step 2: Create KDFHeader object
	kdf_header = KDFHeader(
		kdf_name="argon2id",
		salt=salt,
		params=KDF_PARAMS
	)

	# Step 3: Return it
	return kdf_header

def validate_kdf_params(params: dict) -> bool:
    """
    Validate that KDF parameters meet minimum security requirements.
    
    Args:
        params: Dictionary containing KDF parameters
    
    Returns:
        True if parameters are valid and secure, False otherwise
    """
    # Step 1: Check if all required keys exist
    required_keys = ["time_cost", "memory_cost", "parallelism", "hash_len", "salt_len"]
    
    # Check each required key
    for key in required_keys:
        if key not in params:  # ← Check the 'params' parameter, not KDF_PARAMS
            return False
    
    # Step 2: Validate each parameter value
    if params["time_cost"] < 2:  # ← Use 'params', not KDF_PARAMS
        return False
    
    if params["memory_cost"] < 16 * 1024:  # ← 16MB minimum (not 64MB)
        return False
    
    if params["parallelism"] < 1:  # ← Minimum is 1 (not 3)
        return False
    
    if params["hash_len"] not in [16, 32]:  # ← Must be exactly 16 or 32
        return False
    
    if params["salt_len"] < 8:  # ← Minimum is 8 (not 16)
        return False
    
    # Step 3: All checks passed!
    return True

def serialize_credential(data: dict) -> bytes:
    """
    Convert a credential dictionary to bytes for encryption.
    
    Args:
        data: Dictionary containing credential data
    
    Returns:
        Bytes representation of the credential
    """
    # Convert dict → JSON string → bytes
    json_string = json.dumps(data)
    data_bytes = json_string.encode('utf-8')
    return data_bytes

def deserialize_credential(data: bytes) -> dict:
    """
    Convert bytes back to a credential dictionary after decryption.
    
    Args:
        data: Bytes representation of credential
    
    Returns:
        Dictionary containing credential data
    """
    # Convert bytes → JSON string → dict
    json_string = data.decode('utf-8')
    credential_dict = json.loads(json_string)
    return credential_dict

def encrypt_data(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext with XChaCha20-Poly1305 and return (nonce, ciphertext).
    Ciphertext returned by libsodium already includes the Poly1305 tag.

    Args:
        plaintext: bytes to encrypt
        key: 32-byte key (must be bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)

    Returns:
        (nonce, ciphertext) -- both as raw bytes (nonce is 24 bytes; ciphertext includes tag)
    """
    expected_key_len = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    expected_nonce_len = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

    if not isinstance(key, (bytes, bytearray)) or len(key) != expected_key_len:
        raise ValueError(f"key must be {expected_key_len} bytes")

    if not isinstance(plaintext, (bytes, bytearray)):
        raise ValueError("plaintext must be bytes")

    # Generate a fresh 24-byte nonce for each encryption
    nonce = os.urandom(expected_nonce_len)

    # No AAD here (you can add if you later change signature)
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, b"", nonce, key
    )

    return (nonce, ciphertext)

def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Decrypts ciphertext produced by XChaCha20-Poly1305 (libsodium via PyNaCl bindings).

    Args:
        ciphertext: bytes produced by bindings.crypto_aead_xchacha20poly1305_ietf_encrypt
                    (this includes the Poly1305 auth tag)
        nonce: 24-byte nonce used during encryption (raw bytes)
        key: 32-byte key used for encryption (raw bytes)

    Returns:
        plaintext bytes on success

    Raises:
        ValueError on bad input or authentication failure
    """
    # Validate types
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise ValueError("ciphertext must be bytes")
    if not isinstance(nonce, (bytes, bytearray)):
        raise ValueError("nonce must be bytes")
    if not isinstance(key, (bytes, bytearray)):
        raise ValueError("key must be bytes")

    # Validate lengths
    expected_key_len = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    expected_nonce_len = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    if len(key) != expected_key_len:
        raise ValueError(f"key must be {expected_key_len} bytes")
    if len(nonce) != expected_nonce_len:
        raise ValueError(f"nonce must be {expected_nonce_len} bytes")

    try:
        # No AAD in this signature; if you used AAD during encrypt, pass it here.
        plaintext = bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, b"", nonce, key
        )
        return plaintext
    except Exception as e:
        # libsodium will raise on authentication failure; surface a clear error
        raise ValueError("Decryption failed or authentication tag invalid") from e

    
