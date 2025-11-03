"""
Data models for the credentials manager.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Any, Optional

@dataclass
class KDFHeader:
    """
    Stores Key Derivation Function parameters.
    There should only be one of these in the database.
    """
    kdf_name: str  # "argon2id"
    salt: bytes    # Random salt for key derivation
    params: Dict[str, Any]  # KDF parameters (time_cost, memory_cost, etc.)
    
    # Optional: database primary key
    id: Optional[int] = None

@dataclass
class CredentialRecord:
    """
    Represents a stored credential in the database.
    The ciphertext contains encrypted credential data.
    """
    id: int                    # Primary key
    name: str                  # Plaintext identifier (e.g., "Gmail")
    nonce: bytes               # Encryption nonce
    ciphertext: bytes          # Encrypted credential data
    metadata_json: str         # Plaintext JSON metadata (url, notes, etc.)
    created_at: datetime
    updated_at: datetime
    
    # Optional: decrypted data (only populated when decrypted)
    decrypted_data: Optional[Dict[str, Any]] = None

@dataclass
class SerializedCredential:
    """
    The structure that gets encrypted and stored as ciphertext.
    This is what goes inside the encrypted payload.
    """
    username: str
    password: str
    # Optional fields that can be included
    url: Optional[str] = None
    notes: Optional[str] = None
    custom_fields: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = {
            "username": self.username,
            "password": self.password
        }
        # Only include optional fields if they have values
        if self.url:
            data["url"] = self.url
        if self.notes:
            data["notes"] = self.notes
        if self.custom_fields:
            data["custom_fields"] = self.custom_fields
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SerializedCredential':
        """Create from dictionary after decryption."""
        return cls(
            username=data["username"],
            password=data["password"],
            url=data.get("url"),
            notes=data.get("notes"),
            custom_fields=data.get("custom_fields")
        )

@dataclass
class CredentialMetadata:
    """
    Plaintext metadata that's stored as JSON in the database.
    This is NOT encrypted - use for non-sensitive information.
    """
    url: Optional[str] = None
    notes: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[list[str]] = None
    
    def to_json(self) -> str:
        """Convert to JSON string for storage."""
        import json
        # Remove None values to save space
        data = {k: v for k, v in self.__dict__.items() if v is not None}
        return json.dumps(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CredentialMetadata':
        """Create from JSON string."""
        import json
        data = json.loads(json_str) if json_str else {}
        return cls(**data)

# Example of how these work together:
if __name__ == "__main__":
    # Example KDF header
    kdf_header = KDFHeader(
        kdf_name="argon2id",
        salt=b"16_random_bytes",
        params={"time_cost": 3, "memory_cost": 65536}
    )
    
    # Example credential to encrypt
    credential_data = SerializedCredential(
        username="user@example.com",
        password="secret123",
        url="https://example.com",
        notes="Work account"
    )
    
    # Example database record
    credential_record = CredentialRecord(
        id=1,
        name="Example Service",
        nonce=b"24_random_nonce_bytes",
        ciphertext=b"encrypted_data_here",
        metadata_json='{"url": "https://example.com", "category": "work"}',
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    print("Data models are set up correctly!")
