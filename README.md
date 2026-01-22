# secure_vault_final
Secure Password Manager project on Kali Linux
Project Description

A comprehensive password management system built with Python on Kali Linux, featuring military-grade encryption and enterprise security controls. This application provides secure storage for credentials with AES-256 encryption, bcrypt password hashing, and comprehensive audit logging.

Security & OS Concepts Used
Operating System Concepts:

File system management with JSON storage

Process management for auto-lock timers

Memory management for secure data handling

I/O operations for encryption/decryption

Cybersecurity Concepts:
Cryptography: AES-256, bcrypt, Base64 encoding

Access Control: Authentication & Authorization

Security Monitoring: Audit trails & intrusion detection

Security Policies: Account lockout, auto-lock, password policies

Network Security: IP tracking and geolocation simulation

Quick Start

sudo apt install python3-bcrypt python3-cryptography python3-pil -y
python3 main.py

Features
User registration/login with bcrypt hashing

AES-256 encrypted password storage

Auto-lock after inactivity (1-30 minutes)

Comprehensive audit logging

Password strength checker & generator

Dashboard with security statistics
