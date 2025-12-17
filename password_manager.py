import tkinter as tk
from tkinter import messagebox
import json, os, base64
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    tk.Tk().withdraw()
    messagebox.showerror(
        "Missing Dependency",
        "The 'cryptography' package is required.\nInstall it with:\n\npy -m pip install cryptography"
    )
    raise SystemExit("Missing dependency: cryptography")

VAULT_FILE = "vault.enc"
SALT_FILE = "salt.bin"

# ---------- Security Functions ----------

def load_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
    else:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    return salt

def generate_key(master_password):
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    if not data:
        return {}
    try:
        return json.loads(fernet.decrypt(data))
    except InvalidToken:
        raise InvalidToken("Incorrect master password or corrupted vault")

def save_vault():
    global vault, fernet
    if vault is None or fernet is None:
        return
    encrypted = fernet.encrypt(json.dumps(vault).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

# ---------- GUI Functions ----------

def add_entry():
    site = site_entry.get()
    user = user_entry.get()
    pwd = pass_entry.get()
    if site and user and pwd:
        vault[site] = {"username": user, "password": pwd}
        save_vault()
        messagebox.showinfo("Success", "Password added")
    else:
        messagebox.showwarning("Error", "All fields required")

def retrieve_entry():
    site = site_entry.get()
    if site in vault:
        user_entry.delete(0, tk.END)
        pass_entry.delete(0, tk.END)
        user_entry.insert(0, vault[site]["username"])
        pass_entry.insert(0, vault[site]["password"])
    else:
        messagebox.showerror("Not Found", "No entry found")

def delete_entry():
    site = site_entry.get()
    if site in vault:
        del vault[site]
        save_vault()
        messagebox.showinfo("Deleted", "Entry removed")
    else:
        messagebox.showerror("Error", "Entry not found")

def search_entry():
    keyword = site_entry.get().lower()
    results = [s for s in vault if keyword in s.lower()]
    messagebox.showinfo("Search Results", "\n".join(results) if results else "No matches")

def change_master_password():
    global vault, fernet
    def do_change():
        current_pw = cur_entry.get()
        new_pw = new_entry.get()
        confirm_pw = conf_entry.get()

        if not current_pw or not new_pw or not confirm_pw:
            messagebox.showwarning("Error", "All fields are required")
            return
        if new_pw != confirm_pw:
            messagebox.showerror("Error", "New passwords do not match")
            return
        try:
            current_key = generate_key(current_pw)
            current_fernet = Fernet(current_key)
            if os.path.exists(VAULT_FILE):
                with open(VAULT_FILE, "rb") as f:
                    data = f.read()
                vault_data = json.loads(current_fernet.decrypt(data)) if data else {}
            else:
                vault_data = {}
            # Generate new salt and key
            new_salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=new_salt,
                iterations=100000,
                backend=default_backend()
            )
            new_key = base64.urlsafe_b64encode(kdf.derive(new_pw.encode()))
            new_fernet = Fernet(new_key)
            encrypted = new_fernet.encrypt(json.dumps(vault_data).encode())
            tmp_vault = VAULT_FILE + ".tmp"
            tmp_salt = SALT_FILE + ".tmp"
            with open(tmp_vault, "wb") as f:
                f.write(encrypted)
            with open(tmp_salt, "wb") as f:
                f.write(new_salt)
            os.replace(tmp_vault, VAULT_FILE)
            os.replace(tmp_salt, SALT_FILE)
            # Update globals
            fernet = new_fernet
            vault = vault_data
            messagebox.showinfo("Success", "Master password changed successfully")
            dlg.destroy()
        except InvalidToken:
            messagebox.showerror("Error", "Current master password is incorrect")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change password: {e}")

    dlg = tk.Toplevel()
    dlg.title("Change Master Password")
    dlg.geometry("350x180")

    tk.Label(dlg, text="Current Master Password").pack(pady=(10, 0))
    cur_entry = tk.Entry(dlg, show="*", width=30)
    cur_entry.pack()
    tk.Label(dlg, text="New Master Password").pack(pady=(10, 0))
    new_entry = tk.Entry(dlg, show="*", width=30)
    new_entry.pack()
    tk.Label(dlg, text="Confirm New Password").pack(pady=(10, 0))
    conf_entry = tk.Entry(dlg, show="*", width=30)
    conf_entry.pack()
    tk.Button(dlg, text="Change", command=do_change).pack(pady=10)

# ---------- Login Screen ----------

def login():
    global fernet, vault
    try:
        key = generate_key(master_entry.get())
        fernet = Fernet(key)
        vault = load_vault(fernet)
        login_window.destroy()
        open_main_window()
    except InvalidToken:
        messagebox.showerror("Error", "Wrong master password")
    except Exception as e:
        messagebox.showerror("Error", f"Unexpected error: {e}")
        print("Login error:", e)

# ---------- Main GUI ----------

def open_main_window():
    root = tk.Tk()
    root.title("Secure Password Manager")
    root.geometry("400x300")

    tk.Label(root, text="Website").pack()
    global site_entry
    site_entry = tk.Entry(root, width=40)
    site_entry.pack()

    tk.Label(root, text="Username").pack()
    global user_entry
    user_entry = tk.Entry(root, width=40)
    user_entry.pack()

    tk.Label(root, text="Password").pack()
    global pass_entry
    pass_entry = tk.Entry(root, width=40, show="*")
    pass_entry.pack()

    tk.Button(root, text="Add", command=add_entry).pack(pady=2)
    tk.Button(root, text="Retrieve", command=retrieve_entry).pack(pady=2)
    tk.Button(root, text="Delete", command=delete_entry).pack(pady=2)
    tk.Button(root, text="Search", command=search_entry).pack(pady=2)
    tk.Button(root, text="Change Master Password", command=change_master_password).pack(pady=2)

    root.mainloop()

# ---------- Start App ----------

def start_app():
    global login_window, master_entry
    login_window = tk.Tk()
    login_window.title("Master Login")
    login_window.geometry("300x150")

    tk.Label(login_window, text="Enter Master Password").pack(pady=10)
    master_entry = tk.Entry(login_window, show="*", width=30)
    master_entry.pack()
    tk.Button(login_window, text="Login", command=login).pack(pady=10)
    login_window.mainloop()

if __name__ == "__main__":
    start_app()
