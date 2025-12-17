Password Manager Project 
It is a cyber security project 
A desktop application built in Python with Tkinter that allows users to securely store, manage, and retrieve passwords. All credentials are encrypted locally using AES (Fernet) with a master password. Features include add, retrieve, delete, search entries, and change master password—all offline and fully secure.
The Password Manager is a desktop application developed in Python using Tkinter for the graphical interface and the Cryptography library for strong encryption. It provides a secure, offline solution for managing your passwords and sensitive credentials.

Project Overview

In today’s digital world, securely storing passwords for multiple accounts is critical. This project addresses that need by allowing users to safely store, retrieve, delete, and search their credentials—all in a local, encrypted vault. The application ensures that no sensitive information is stored in plain text, protecting users from potential security breaches.

Key Features

Master Password Authentication: Protects access to the vault. Only users with the correct master password can access stored credentials.

AES Encryption with Fernet: All passwords and usernames are encrypted using strong symmetric encryption with secure key derivation (PBKDF2 + SHA256).

Encrypted Local Storage: Credentials are stored in a local JSON file (vault.enc) that is fully encrypted and safe from unauthorized access.

Password Management Functionalities:
Add new entries (Website, Username, Password)

Retrieve saved credentials

Delete entries securely

Search credentials by website name

Change Master Password: Safely update the master password without losing existing data.

User-Friendly GUI: Provides an intuitive and clean interface for easy navigation and interaction.

Technologies Used

Python 3 – Core programming language

Tkinter – GUI development

Cryptography Library – AES (Fernet) encryption, PBKDF2 key derivation

JSON – Encrypted local storage

Benefits and Use Cases

Fully offline and secure; no data is transmitted over the internet.

Provides a safe and reliable way to manage personal passwords.

Helps in learning cryptography, secure local storage, and GUI development.

Ideal for personal use or as an educational project in cybersecurity and software engineering.
