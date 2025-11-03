from config import DATABASE_PATH
import sqlite3
import json
from models import KDFHeader
from crypto_utils import generate_kdf_header
from crypto_utils import serialize_credential
from crypto_utils import encrypt_data
from datetime import datetime
from models import CredentialMetadata
from crypto_utils import decrypt_data
from crypto_utils import deserialize_credential
from models import CredentialRecord
from typing import List

# Schema definition (string ends before the function)
schema = """
CREATE TABLE IF NOT EXISTS kdf_header (
    id INTEGER PRIMARY KEY,
    kdf_name TEXT NOT NULL,
    salt BLOB NOT NULL,
    params TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    name TEXT NOT NULL, 
    nonce BLOB NOT NULL, 
    ciphertext BLOB NOT NULL,
    metadata_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL, 
    updated_at TEXT NOT NULL
);
"""

def init_database() -> None:
    """
    Initialize the database and create tables if they don't exist.
    """
    path = DATABASE_PATH
    conn = sqlite3.connect(path)
    try:
        conn.executescript(schema)
        conn.commit()
    finally:
        conn.close()

def get_or_create_kdf_header() -> KDFHeader:
    """
    Get the KDF header from database, or create one if it doesn't exist.
    
    Returns:
        KDFHeader object
    """
    # Step 1: Open the database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Step 2: Try to find existing KDF header
    cursor.execute('SELECT * FROM kdf_header WHERE id = 1')
    row = cursor.fetchone()  # Returns None if not found
    
    # Step 3: Check if we found something
    if row:
        # We found it! Load it from the database
        # row = (id, kdf_name, salt, params_json)
        
        kdf_header = KDFHeader(
            id=row[0],                  # id
            kdf_name=row[1],            # 'argon2id'
            salt=row[2],                # bytes
            params=json.loads(row[3])   # Convert JSON string to dict
        )
        
        conn.close()
        return kdf_header
    
    else:
        # Didn't find it! Create a new one
        
        # Generate new KDF header using your crypto function
        new_header = generate_kdf_header()
        
        # Convert params dict to JSON string
        params_json = json.dumps(new_header.params)
        
        # Save to database
        cursor.execute('''
            INSERT INTO kdf_header (id, kdf_name, salt, params)
            VALUES (?, ?, ?, ?)
        ''', (1, new_header.kdf_name, new_header.salt, params_json))
        
        conn.commit()
        conn.close()
        
        # Set the id
        new_header.id = 1
        
        return new_header

def insert_credential(name: str, credential_data: dict, key: bytes) -> int:
    plaintext_bytes = serialize_credential(credential_data)
    nonce, ciphertext = encrypt_data(plaintext_bytes, key)
    
    # Use the class (better!)
    metadata = CredentialMetadata(
        url=credential_data.get("url"),
        notes=credential_data.get("notes"),
        category=credential_data.get("category"),
        tags=credential_data.get("tags")
    )
    metadata_json = metadata.to_json()
    
    now = datetime.now().isoformat()
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO credentials(name, nonce, ciphertext, metadata_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (name, nonce, ciphertext, metadata_json, now, now))
    
    conn.commit()
    credential_id = cursor.lastrowid
    conn.close()
    
    return credential_id

def get_credential(credential_id: int, key: bytes) -> dict:
    """
    Retrieve and decrypt a credential from the database.
    
    Args:
        credential_id: The ID of the credential to retrieve
        key: Encryption key (32 bytes)
    
    Returns:
        Dictionary with decrypted credential data
    
    Raises:
        ValueError: If credential not found or decryption fails
    """
    # Connect to database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Query for the credential
    cursor.execute('''
        SELECT nonce, ciphertext FROM credentials WHERE id = ?
    ''', (credential_id,))
    
    row = cursor.fetchone()
    conn.close()
    
    # Check if found
    if not row:
        raise ValueError(f"Credential with ID {credential_id} not found")
    
    # Extract nonce and ciphertext
    nonce = row[0]
    ciphertext = row[1]
    
    # Decrypt and deserialize
    try:
        plaintext_bytes = decrypt_data(ciphertext, nonce, key)
        plaintext = deserialize_credential(plaintext_bytes)
        return plaintext
    except Exception as e:
        raise ValueError(f"Failed to decrypt credential (wrong password?): {e}")

def list_credentials() -> List[CredentialRecord]:
    """
    List all credentials in the database (metadata only, not decrypted).
    
    Returns:
        List of CredentialRecord objects (ordered by creation date, newest first)
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Explicitly list columns (don't use SELECT *)
    cursor.execute('''
        SELECT id, name, nonce, ciphertext, metadata_json, created_at, updated_at
        FROM credentials
        ORDER BY created_at DESC
    ''')
    
    rows = cursor.fetchall()
    conn.close()
    
    credentials = []
    
    for row in rows:
        cred = CredentialRecord(
            id=row[0],
            name=row[1],
            nonce=row[2],
            ciphertext=row[3],
            metadata_json=row[4],                      # ← Added!
            created_at=datetime.fromisoformat(row[5]), # ← Convert to datetime!
            updated_at=datetime.fromisoformat(row[6])  # ← Convert to datetime!
        )
        credentials.append(cred)
    
    return credentials

def update_credential(credential_id: int, new_data: dict, key: bytes) -> bool:
    """
    Update an existing credential with new data.
    
    Args:
        credential_id: The ID of the credential to update
        new_data: Dictionary with new credential data
        key: Encryption key (32 bytes)
    
    Returns:
        True if successful, False if credential not found
    """
    # Connect to database
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Check if credential exists
    cursor.execute('''
        SELECT id FROM credentials
        WHERE id = ?
    ''', (credential_id,))
    
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False
    
    # Serialize and encrypt new data
    plaintext_bytes = serialize_credential(new_data)  # ← Fixed typo
    nonce, ciphertext = encrypt_data(plaintext_bytes, key)
    
    # Prepare metadata
    metadata = CredentialMetadata(
        url=new_data.get("url"),
        notes=new_data.get("notes"),
        category=new_data.get("category"),
        tags=new_data.get("tags")
    )
    metadata_json = metadata.to_json()
    
    # Get current timestamp
    now = datetime.now().isoformat()
    
    # Update database
    cursor.execute('''
        UPDATE credentials 
        SET nonce = ?,
            ciphertext = ?, 
            metadata_json = ?, 
            updated_at = ?
        WHERE id = ?
    ''', (nonce, ciphertext, metadata_json, now, credential_id))
    #                                        ^^^  ^^^^^^^^^^^^^^
    #                                    Fixed!      Added!
    
    conn.commit()
    conn.close()
    
    return True

def delete_credential(credential_id: int) -> bool:
    """
    Delete a credential from the database.
    
    Args:
        credential_id: The ID of the credential to delete
    
    Returns:
        True if deleted successfully, False if not found
    """
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Check if credential exists
    cursor.execute('SELECT id FROM credentials WHERE id = ?', (credential_id,))
    #                                ^^^^^^^^^^^ Fixed typo!
    row = cursor.fetchone()
    
    if not row:
        conn.close()
        return False
    
    # Delete the credential
    try:
        cursor.execute('DELETE FROM credentials WHERE id = ?', (credential_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False


