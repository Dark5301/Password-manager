# main.py
"""
🔐 Secure Password Manager
A command-line password manager with military-grade encryption.
"""

from database import (
    init_database,
    get_or_create_kdf_header,
    insert_credential,
    get_credential,
    list_credentials,
    update_credential,
    delete_credential
)
from crypto_utils import derive_key
import getpass
import sys
import json
import time


# ============================================================================
#                           BEAUTIFUL FORMATTING
# ============================================================================

def clear_screen():
    """Clear the terminal screen."""
    print("\033[H\033[J", end="")


def print_banner():
    """Print beautiful ASCII art banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║              🔐  SECURE PASSWORD MANAGER  🔐                     ║
    ║                                                                   ║
    ║            Military-Grade Encryption (AES-256 + Argon2)          ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_header(title):
    """Print a beautiful section header."""
    width = 71
    print("\n" + "╔" + "═" * (width - 2) + "╗")
    padding = (width - len(title) - 2) // 2
    print("║" + " " * padding + title + " " * (width - len(title) - padding - 2) + "║")
    print("╚" + "═" * (width - 2) + "╝")


def print_divider():
    """Print a visual divider."""
    print("─" * 71)


def print_success(message):
    """Print success message."""
    print(f"\n✅ {message}")


def print_error(message):
    """Print error message."""
    print(f"\n❌ {message}")


def print_warning(message):
    """Print warning message."""
    print(f"\n⚠️  {message}")


def print_info(message):
    """Print info message."""
    print(f"\n💡 {message}")


def loading_animation(message, duration=1):
    """Show a loading animation."""
    print(f"\n{message}", end="", flush=True)
    for _ in range(3):
        time.sleep(duration / 3)
        print(".", end="", flush=True)
    print(" ✓")


def press_enter_to_continue():
    """Wait for user to press Enter."""
    input("\n🔹 Press Enter to continue...")


# ============================================================================
#                              MAIN APPLICATION
# ============================================================================

def main():
    """Main application entry point."""
    clear_screen()
    print_banner()
    
    # Initialize database
    loading_animation("📂 Initializing secure vault")
    init_database()
    
    # Get or create KDF header
    loading_animation("🔑 Loading encryption configuration")
    kdf_header = get_or_create_kdf_header()
    
    # Check if this is first run
    is_first_run = not has_credentials()
    
    if is_first_run:
        print_info("Welcome! This appears to be your first time.")
        print("   Please create a strong master password.")
        print("   ⚠️  Remember it - it CANNOT be recovered!")
    
    # Get master password
    print("\n" + "─" * 71)
    while True:
        master_password = getpass.getpass("🔒 Enter master password: ")
        
        if not master_password:
            print_error("Master password cannot be empty!")
            continue
        
        if is_first_run and len(master_password) < 8:
            print_error("Master password must be at least 8 characters!")
            continue
        
        if is_first_run:
            confirm = getpass.getpass("🔒 Confirm master password: ")
            if master_password != confirm:
                print_error("Passwords don't match! Try again.")
                continue
        
        break
    
    print("─" * 71)
    
    # Derive encryption key
    loading_animation("🔐 Deriving encryption key (this may take a moment)")
    
    try:
        key = derive_key(master_password, kdf_header.salt)
    except Exception as e:
        print_error(f"Failed to derive key: {e}")
        sys.exit(1)
    
    # Verify password by trying to decrypt (if credentials exist)
    if not is_first_run:
        try:
            # Try to get first credential to verify password
            creds = list_credentials()
            if creds:
                get_credential(creds[0].id, key)
        except:
            print_error("Incorrect master password!")
            sys.exit(1)
    
    print_success("Vault unlocked successfully!")
    time.sleep(0.5)
    
    # Enter main menu
    main_menu(key)


def has_credentials():
    """Check if any credentials exist."""
    return len(list_credentials()) > 0


# ============================================================================
#                              MAIN MENU
# ============================================================================

def main_menu(key):
    """Display main menu and handle user choices."""
    while True:
        clear_screen()
        
        # Show status
        creds = list_credentials()
        print("\n" + "═" * 71)
        print(f"  🔓 Vault Unlocked  |  📊 {len(creds)} credential(s) stored")
        print("═" * 71)
        
        # Menu options
        menu = """
    ┌─────────────────────────────────────────────────────────────────┐
    │                         MAIN MENU                               │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │   1. ➕  Add New Credential                                     │
    │   2. 📋  List All Credentials                                   │
    │   3. 👁️   View Credential (Show Password)                       │
    │   4. ✏️   Update Credential                                      │
    │   5. 🗑️   Delete Credential                                      │
    │   6. 🔒  Lock Vault & Exit                                      │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
        """
        print(menu)
        
        choice = input("    ▶️  Choose an option (1-6): ").strip()
        
        if choice == "1":
            add_credential_menu(key)
        elif choice == "2":
            list_credentials_menu()
        elif choice == "3":
            view_credential_menu(key)
        elif choice == "4":
            update_credential_menu(key)
        elif choice == "5":
            delete_credential_menu()
        elif choice == "6":
            clear_screen()
            print("\n" + "═" * 71)
            print("  🔒 Vault locked. Your secrets are safe!")
            print("═" * 71)
            print("\n  👋 Thank you for using Secure Password Manager!\n")
            sys.exit(0)
        else:
            print_error("Invalid option. Please choose 1-6.")
            time.sleep(1)


# ============================================================================
#                           MENU FUNCTIONS
# ============================================================================

def add_credential_menu(key):
    """Add a new credential."""
    clear_screen()
    print_header("➕  ADD NEW CREDENTIAL")
    
    print("\n📝 Enter credential details:\n")
    
    # Required fields
    name = input("  🏷️  Name (e.g., 'Gmail Account'): ").strip()
    if not name:
        print_error("Name is required!")
        press_enter_to_continue()
        return
    
    username = input("  👤 Username/Email: ").strip()
    if not username:
        print_error("Username is required!")
        press_enter_to_continue()
        return
    
    password = getpass.getpass("  🔑 Password: ")
    if not password:
        print_error("Password is required!")
        press_enter_to_continue()
        return
    
    # Optional fields
    print("\n📎 Optional fields (press Enter to skip):\n")
    url = input("  🌐 URL: ").strip() or None
    notes = input("  📝 Notes: ").strip() or None
    category = input("  🏷️  Category: ").strip() or None
    
    # Build credential data
    credential_data = {
        "username": username,
        "password": password
    }
    
    if url:
        credential_data["url"] = url
    if notes:
        credential_data["notes"] = notes
    if category:
        credential_data["category"] = category
    
    # Save
    loading_animation("🔐 Encrypting and saving")
    
    try:
        cred_id = insert_credential(name, credential_data, key)
        print_success(f"Credential '{name}' added successfully! (ID: {cred_id})")
    except Exception as e:
        print_error(f"Failed to add credential: {e}")
    
    press_enter_to_continue()


def list_credentials_menu():
    """List all credentials."""
    clear_screen()
    print_header("📋  ALL CREDENTIALS")
    
    credentials = list_credentials()
    
    if not credentials:
        print_info("No credentials stored yet.")
        print("      Use option 1 to add your first credential!")
        press_enter_to_continue()
        return
    
    print(f"\n📊 You have {len(credentials)} credential(s):\n")
    
    for i, cred in enumerate(credentials, 1):
        try:
            metadata = json.loads(cred.metadata_json) if cred.metadata_json else {}
        except:
            metadata = {}
        
        print("┌" + "─" * 69 + "┐")
        print(f"│ #{cred.id:<3} {cred.name:<62} │")
        print("├" + "─" * 69 + "┤")
        
        if metadata.get("url"):
            print(f"│   🌐 {metadata['url']:<63} │")
        if metadata.get("category"):
            print(f"│   🏷️  {metadata['category']:<62} │")
        if metadata.get("notes"):
            notes = metadata['notes'][:60] + "..." if len(metadata['notes']) > 60 else metadata['notes']
            print(f"│   📝 {notes:<63} │")
        
        print(f"│   🕐 Created: {str(cred.created_at):<54} │")
        print("└" + "─" * 69 + "┘\n")
    
    press_enter_to_continue()


def view_credential_menu(key):
    """View a credential (decrypt and show password)."""
    clear_screen()
    print_header("👁️  VIEW CREDENTIAL")
    
    credentials = list_credentials()
    
    if not credentials:
        print_info("No credentials stored yet.")
        press_enter_to_continue()
        return
    
    print("\n📋 Available credentials:\n")
    for cred in credentials:
        print(f"  {cred.id}. {cred.name}")
    
    print()
    try:
        cred_id = int(input("▶️  Enter credential ID to view: ").strip())
    except ValueError:
        print_error("Invalid ID! Must be a number.")
        press_enter_to_continue()
        return
    
    loading_animation("🔓 Decrypting credential")
    
    try:
        credential_data = get_credential(cred_id, key)
        
        print("\n┌" + "─" * 69 + "┐")
        print(f"│ CREDENTIAL DETAILS (ID: {cred_id})" + " " * (69 - len(f"CREDENTIAL DETAILS (ID: {cred_id})") - 1) + "│")
        print("├" + "─" * 69 + "┤")
        print(f"│ 👤 Username: {credential_data['username']:<54} │")
        print(f"│ 🔑 Password: {credential_data['password']:<54} │")
        
        if credential_data.get("url"):
            print(f"│ 🌐 URL: {credential_data['url']:<60} │")
        if credential_data.get("notes"):
            print(f"│ 📝 Notes: {credential_data['notes']:<58} │")
        if credential_data.get("category"):
            print(f"│ 🏷️  Category: {credential_data['category']:<55} │")
        
        print("└" + "─" * 69 + "┘")
        
    except ValueError as e:
        print_error(str(e))
    except Exception as e:
        print_error(f"Failed to retrieve credential: {e}")
    
    press_enter_to_continue()


def update_credential_menu(key):
    """Update an existing credential."""
    clear_screen()
    print_header("✏️  UPDATE CREDENTIAL")
    
    credentials = list_credentials()
    
    if not credentials:
        print_info("No credentials stored yet.")
        press_enter_to_continue()
        return
    
    print("\n📋 Available credentials:\n")
    for cred in credentials:
        print(f"  {cred.id}. {cred.name}")
    
    print()
    try:
        cred_id = int(input("▶️  Enter credential ID to update: ").strip())
    except ValueError:
        print_error("Invalid ID! Must be a number.")
        press_enter_to_continue()
        return
    
    # Get current data
    try:
        current_data = get_credential(cred_id, key)
    except ValueError as e:
        print_error(str(e))
        press_enter_to_continue()
        return
    
    print("\n📋 Current values:")
    print(f"  Username: {current_data['username']}")
    print(f"  Password: {'*' * len(current_data['password'])}")
    
    print("\n📝 Enter new values (press Enter to keep current):\n")
    
    new_username = input(f"  👤 Username [{current_data['username']}]: ").strip()
    new_password = getpass.getpass("  🔑 Password [****]: ")
    
    if not new_username:
        new_username = current_data['username']
    if not new_password:
        new_password = current_data['password']
    
    print("\n📎 Optional fields:\n")
    url = input("  🌐 URL: ").strip() or None
    notes = input("  📝 Notes: ").strip() or None
    category = input("  🏷️  Category: ").strip() or None
    
    new_data = {
        "username": new_username,
        "password": new_password
    }
    
    if url:
        new_data["url"] = url
    if notes:
        new_data["notes"] = notes
    if category:
        new_data["category"] = category
    
    loading_animation("🔐 Encrypting and updating")
    
    try:
        result = update_credential(cred_id, new_data, key)
        
        if result:
            print_success("Credential updated successfully!")
        else:
            print_error("Credential not found.")
            
    except Exception as e:
        print_error(f"Failed to update credential: {e}")
    
    press_enter_to_continue()


def delete_credential_menu():
    """Delete a credential."""
    clear_screen()
    print_header("🗑️  DELETE CREDENTIAL")
    
    credentials = list_credentials()
    
    if not credentials:
        print_info("No credentials stored yet.")
        press_enter_to_continue()
        return
    
    print("\n📋 Available credentials:\n")
    for cred in credentials:
        print(f"  {cred.id}. {cred.name}")
    
    print()
    try:
        cred_id = int(input("▶️  Enter credential ID to delete: ").strip())
    except ValueError:
        print_error("Invalid ID! Must be a number.")
        press_enter_to_continue()
        return
    
    print_warning("This action cannot be undone!")
    confirm = input("   Type 'DELETE' to confirm: ").strip()
    
    if confirm != "DELETE":
        print_error("Deletion cancelled.")
        press_enter_to_continue()
        return
    
    loading_animation("🗑️  Deleting credential")
    
    try:
        result = delete_credential(cred_id)
        
        if result:
            print_success("Credential deleted successfully!")
        else:
            print_error("Credential not found.")
            
    except Exception as e:
        print_error(f"Failed to delete credential: {e}")
    
    press_enter_to_continue()


# ============================================================================
#                              RUN APPLICATION
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print("\n\n" + "═" * 71)
        print("  🔒 Vault locked. Your secrets are safe!")
        print("═" * 71)
        print("\n  👋 Goodbye!\n")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
