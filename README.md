# Shared Secrets UI
Exchange data securely over an insecure connection, using Diffie–Hellman Key Exchange

---------------------------
# Guide
Head over to the [releases](https://github.com/TernaryFortress/shared-secrets-ui/releases/tag/release) section and download the appropriate binary or executable for your operating system.

These are compiled using pyinstaller directly on the source, and is composed in tkinter.

--------------------------
# What is Diffie-Hellman Key Exchange?
Diffie-Hellman Key Exchange (DHKE) is a method for two parties to securely share a secret key over an insecure channel without directly transmitting the key itself.
Key Points:

- Public Parameters: Both parties agree on common values.
- Private Keys: Each party selects a private key that is never shared.
- Public Keys: They exchange public keys derived from their private keys.
- Shared Secret: Each party computes the same shared secret key using their private key and the other party's public key.

Why It Works:
- Mathematically: DHKE relies on the commutative nature of scalar multiplication, in this case over an elliptic curve.
- Simplified Example: Private Key A * Public Key B = Private Key B * Public Key A
- Perfect Forward Secrecy: So long as both private keys are secret, nobody else can derive the encryption key.
- Security: The method relies on the difficulty of certain mathematical problems, making it hard for attackers to derive the private keys from the public information.
- No Direct Key Sharing: Since the actual secret key is never sent over the channel, it remains secure from eavesdroppers.

