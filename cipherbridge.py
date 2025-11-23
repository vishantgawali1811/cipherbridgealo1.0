#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os

# ---------- BANNERS ----------
CIPHERBRIDGE_BANNER = r"""
                                                         ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ██████╗ ██████╗ ██╗██████╗  ██████╗ ███████╗     
                                                        ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝    
                                                        ██║     ██║██████╔╝███████║█████╗  ██████╔╝██████╔╝██████╔╝██║██║  ██║██║  ███╗█████╗      
                                                        ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔══██╗██╔══██╗██║██║  ██║██║   ██║██╔══╝      
                                                        ╚██████╗██║██║     ██║  ██║███████╗██║  ██║██████╔╝██║  ██║██║██████╔╝╚██████╔╝███████╗    
                                                         ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝    
"""

SECOND_BANNER = r"""
       ______                            __  _                _____                                __       _         _____                     __            _ __  __       ___                                        __       _         _____                      _ __       
      / ____/___  ____  ____  ___  _____/ /_(_)___  ____ _   / ___/__  ______ ___  ____ ___  ___  / /______(_)____   / ___/____  ___  ___  ____/ /  _      __(_) /_/ /_     /   |  _______  ______ ___  ____ ___  ___  / /______(_)____   / ___/___  _______  _______(_) /___  __
     / /   / __ \/ __ \/ __ \/ _ \/ ___/ __/ / __ \/ __ `/   \__ \/ / / / __ `__ \/ __ `__ \/ _ \/ __/ ___/ / ___/   \__ \/ __ \/ _ \/ _ \/ __  /  | | /| / / / __/ __ \   / /| | / ___/ / / / __ `__ \/ __ `__ \/ _ \/ __/ ___/ / ___/   \__ \/ _ \/ ___/ / / / ___/ / __/ / / /
    / /___/ /_/ / / / / / / /  __/ /__/ /_/ / / / / /_/ /   ___/ / /_/ / / / / / / / / / / /  __/ /_/ /  / / /__    ___/ / /_/ /  __/  __/ /_/ /   | |/ |/ / / /_/ / / /  / ___ |(__  ) /_/ / / / / / / / / / / /  __/ /_/ /  / / /__    ___/ /  __/ /__/ /_/ / /  / / /_/ /_/ / 
    \____/\____/_/ /_/_/ /_/\___/\___/\__/_/_/ /_/\__, /   /____/\__, /_/ /_/ /_/_/ /_/ /_/\___/\__/_/  /_/\___/   /____/ .___/\___/\___/\__,_/    |__/|__/_/\__/_/ /_/  /_/  |_/____/\__, /_/ /_/ /_/_/ /_/ /_/\___/\__/_/  /_/\___/   /____/\___/\___/\__,_/_/  /_/\__/\__, (_)
                                                 /____/         /____/                                                 /_/                                                           /____/                                                                             /____/   
"""

# ---------- Fake AES (for demo only) ----------
def aes_encrypt(key: str, plaintext: str):
    print("\n[DEBUG] AES Encrypt → Using key:", key)
    ciphertext = "".join(chr(ord(p) ^ ord(key[i % len(key)])) for i, p in enumerate(plaintext))
    print("[DEBUG] AES Raw XOR Result:", ciphertext)
    encoded = base64.b64encode(ciphertext.encode()).decode()
    print("[DEBUG] AES Base64 Encoded Cipher:", encoded)
    return encoded

def aes_decrypt(key: str, ciphertext_b64: str):
    print("\n[DEBUG] AES Decrypt → Using key:", key)
    ciphertext = base64.b64decode(ciphertext_b64).decode()
    print("[DEBUG] Base64 Decoded Cipher:", ciphertext)
    plaintext = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(ciphertext))
    print("[DEBUG] AES Decrypted Plaintext:", plaintext)
    return plaintext

# ---------- Fake ElGamal (numeric encryption demo) ----------
p = 257       # prime number (modulus)
e = 3         # public key exponent
d = 171       # private key exponent

def elgamal_encrypt(key: str):
    print("\n[DEBUG] ElGamal Encrypt → Original AES Key:", key)
    ascii_values = [ord(ch) for ch in key]
    print("[DEBUG] AES Key ASCII:", ascii_values)
    enc_values = [(val ** e) % p for val in ascii_values]
    print("[DEBUG] ElGamal Encrypted Key:", enc_values)
    return enc_values

def elgamal_decrypt(enc_values: list):
    print("\n[DEBUG] ElGamal Decrypt → Received Encrypted ASCII:", enc_values)
    dec_values = [(val ** d) % p for val in enc_values]
    print("[DEBUG] AES Key after ElGamal Decrypt (ASCII):", dec_values)
    dec_key = "".join(chr(val) for val in dec_values)
    print("[DEBUG] ElGamal Decrypted AES Key:", dec_key)
    return dec_key

# ---------- Hybrid Encrypt ----------
def hybrid_encrypt(plaintext: str, aes_key: str):
    print("\n=== HYBRID ENCRYPT START ===")
    ciphertext = aes_encrypt(aes_key, plaintext)
    enc_aes_key = elgamal_encrypt(aes_key)
    package = {"elgamal": enc_aes_key, "aes": {"ciphertext": ciphertext}}
    print("\n[DEBUG] Final Encryption Package:", package)
    print("=== HYBRID ENCRYPT END ===\n")
    return json.dumps(package)

# ---------- Hybrid Decrypt ----------
def hybrid_decrypt(package_json: str):
    print("\n=== HYBRID DECRYPT START ===")
    data = json.loads(package_json)
    print("[DEBUG] Received Package:", data)
    aes_key = elgamal_decrypt(data["elgamal"])
    plaintext = aes_decrypt(aes_key, data["aes"]["ciphertext"])
    print("=== HYBRID DECRYPT END ===\n")
    return plaintext

# ---------- MAIN ----------
if __name__ == "__main__":
    os.system("clear")
    print(CIPHERBRIDGE_BANNER)
    print(SECOND_BANNER)
    print("\n💡 Using ElGamal parameters:")
    print(f"Prime (p) = 257\nPublic exponent (e) = 3\nPrivate exponent (d) = 171\n")

    print("🧠  Hybrid Encryption Demo — by Vishant\n")

    try:
        message = input("💬 Enter a message to encrypt: ")
        aes_key = input("🔑 Enter an AES key: ")

        encrypted = hybrid_encrypt(message, aes_key)
        print("\n🔒 Encrypted Package (JSON):\n", encrypted, "\n")

        decrypted = hybrid_decrypt(encrypted)
        print("🔓 Decrypted Message:", decrypted)

    except Exception as e:
        print("\n❌ Error occurred:", e)

