# 🔐 Password Manager

A **secure, modern, and extensible password management system** built in Python.
This project implements **per-record encryption**, **strong password hashing**, and **vault-based credential storage** using industry-grade cryptographic standards.

## 🚀 Overview

The Password Manager enables users to safely store, retrieve, and manage their credentials locally in an encrypted vault.
It uses **Argon2** for key derivation and **NaCl (libsodium)** for authenticated encryption — ensuring your data remains private even if the vault file is compromised.

## 🧩 Core Features

* **🔒 End-to-end encryption:** Each record is encrypted individually with a unique key and nonce.
* **🗄️ Secure storage:** Credentials are stored in a local SQLite database with encrypted blobs.
* **🧠 Strong key derivation:** Argon2 is used for generating cryptographic keys from master passwords.
* **📦 Configurable design:** All cryptographic and storage parameters are centralized in `config.py`.
* **📚 Modular architecture:** Clean separation between configuration, crypto utilities, models, and storage logic.
* **⚡ CLI-ready main entry point:** `main.py` provides an easy-to-extend interactive interface.

## 🏗️ Project Structure

```
password-manager/
│
├── main.py             # CLI entry point – handles user interactions
├── config.py           # Application-wide constants and parameters
├── crypto_utils.py     # Encryption, decryption, key derivation utilities
├── database.py         # Vault storage and database operations
├── models.py           # Data models for credentials and vault schema
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
```
## 🔧 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Dark5301/Password-manager.git
   cd Password-manager
   ```

2. **Create and activate a virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate      # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

## 🧠 Usage

1. **Run the main application**

   ```bash
   python3 main.py
   ```

2. **Set your master password**

   * On first run, you’ll be prompted to create a secure master password.
   * The master password is **never stored** — it’s used to derive your encryption key.

3. **Add, view, or delete credentials**

   * Store new credentials (e.g., website login, API token).
   * Retrieve existing credentials after authentication.
   * Delete or update records securely.

## 🔐 Security Design

| Component      | Implementation                       | Description                                            |
| -------------- | ------------------------------------ | ------------------------------------------------------ |
| Key Derivation | `Argon2`                             | Memory-hard KDF to resist brute-force attacks.         |
| Encryption     | `NaCl SecretBox (XSalsa20-Poly1305)` | Authenticated encryption for each record.              |
| Vault Storage  | `SQLite`                             | Encrypted blobs per row, supporting efficient updates. |
| Serialization  | `CBOR2`                              | Compact binary encoding for structured data.           |

## ⚙️ Configuration

The `config.py` file centralizes cryptographic parameters:

* **SALT_SIZE** – Salt length for Argon2 key derivation
* **ARGON2_PARAMS** – Memory cost, parallelism, and iterations
* **DB_PATH** – Path to the local encrypted SQLite vault

You can safely adjust these settings based on performance and security requirements.

## 🧪 Example

```bash
$ python main.py
Enter master password: ********

[1] Add a new credential
[2] View stored credentials
[3] Delete a credential
[4] Exit
```

Each operation automatically handles encryption and decryption transparently.

## 🧰 Dependencies

All dependencies are listed in [`requirements.txt`](requirements.txt):

```
pynacl==1.5.0
cbor2==5.4.6
argon2-cffi==21.3.0
```

## 🛡️ Security Best Practices

* Use a **strong, unique master password** (minimum 12–16 characters).
* Do **not reuse** your master password elsewhere.
* Backup your vault file securely — losing it means losing access permanently.
* Periodically update dependencies to patch cryptographic libraries.

## 🧩 Future Enhancements

* 🔑 Password generator module
* 🌐 Web / GUI interface
* ☁️ Secure cloud vault synchronization
* 🔄 Auto-lock after inactivity
* 🧾 Encrypted export/import format

## 📜 License

This project is released under the **MIT License**.
Feel free to use, modify, and distribute — with proper attribution.

## 🤝 Contributing

Contributions are welcome!
If you find bugs or have feature suggestions:

1. Fork the repository
2. Create a new branch (`feature/new-module`)
3. Submit a pull request with a clear description
