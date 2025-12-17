🗝️ Secure Password Manager

A simple, secure password manager built with Python and Tkinter. It encrypts your passwords using Fernet symmetric encryption and allows you to safely store, retrieve, search, and copy credentials.

✅ Features

First-run default master password: MySecret123

Add, retrieve, delete website credentials

Change master password securely

Search saved websites

Copy username/password to clipboard

Vault encrypted using AES (Fernet)

Salt stored securely for key derivation

🛠️ Technologies Used

Python 3

Tkinter (GUI)

Cryptography library (cryptography package)

JSON (for storing vault data)

💻 Installation

Clone this repository:

git clone https://github.com/yourusername/password-manager.git
cd password-manager


Install dependencies:

pip install cryptography


Run the application:

python password_manager.py

🚀 Usage

First Run

Default master password is:

MySecret123


Vault will be initialized automatically.

Login

Enter your master password to unlock the vault.

Add Entry

Enter Website, Username, and Password, then click Add.

Retrieve Entry

Enter the Website name, then click Retrieve.

Delete Entry

Enter the Website name, then click Delete.

Change Master Password

Click Change Master Password and follow the prompts.

Search

Enter a keyword in the Website field and click Search.

Copy Username / Password

Enter the website and click Copy Username or Copy Password.

🔐 Security Notes

Vault is encrypted with Fernet symmetric encryption.

The master password is never stored in plain text.

Salt is stored in salt.bin for secure key derivation.

Changing the master password re-encrypts the vault with a new key and salt.

📂 Files

password_manager.py — Main application code

vault.enc — Encrypted vault file (auto-generated)

salt.bin — Salt for key derivation (auto-generated)

💡 Screenshots

(Optional: Add screenshots of your GUI here)

📌 License

This project is licensed under the MIT License.

If you want, I can also write a GitHub-ready commit structure and push instructions for VSCode, so you can upload this project to GitHub in one go.

Do you want me to do that next?
