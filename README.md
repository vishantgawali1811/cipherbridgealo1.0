# cipherbridgealo1.0

                 ┌─────────────────────┐
                 │      START          │
                 └─────────┬───────────┘
                           │
                           ▼
               ┌────────────────────────┐
               │ Print banners & info   │
               └─────────┬──────────────┘
                           │
                           ▼
          ┌────────────────────────────────┐
          │ Take user input:               │
          │  - message                     │
          │  - AES key                     │
          └─────────┬──────────────────────┘
                    │
                    ▼
        ┌──────────────────────────┐
        │   HYBRID ENCRYPT START   │
        └──────────┬───────────────┘
                   │
                   ▼
    ┌────────────────────────────────┐
    │ AES Encrypt:                   │
    │ 1. XOR plaintext with AES key  │
    │ 2. Convert result to Base64    │
    └───────────┬────────────────────┘
                │
                ▼
   ┌──────────────────────────────────┐
   │ ElGamal Encrypt AES key:         │
   │ 1. Convert each char → ASCII     │
   │ 2. Do (value^e mod p)            │
   └──────────┬───────────────────────┘
              │
              ▼
     ┌────────────────────────────────┐
     │ Build JSON package:            │
     │  { "elgamal": [...],           │
     │    "aes": {"ciphertext": "..."}│
     │  }                              │
     └─────────┬──────────────────────┘
               │
               ▼
     ┌───────────────────────────┐
     │   HYBRID DECRYPT START    │
     └──────────┬────────────────┘
                │
                ▼
   ┌──────────────────────────────────┐
   │ ElGamal Decrypt AES key:         │
   │ 1. Do (value^d mod p)            │
   │ 2. Convert ASCII → characters    │
   └───────────┬──────────────────────┘
               │
               ▼
    ┌────────────────────────────┐
    │ AES Decrypt:               │
    │ 1. Base64 decode           │
    │ 2. XOR with AES key        │
    │ 3. Get original plaintext  │
    └──────────┬─────────────────┘
               │
               ▼
          ┌─────────────────┐
          │ Print plaintext │
          └─────────┬───────┘
                    │
                    ▼
                ┌─────────┐
                │  END    │
                └─────────┘
