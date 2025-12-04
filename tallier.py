"""
tallier.py
This script is responsible for:
1. Generating an RSA key pair for encrypting/decrypting votes.
   - The public key is given to clients.
   - The private key is kept secret.
2. After the election, loading the encrypted ballot box,
   decrypting each ballot, and tallying the final results.
"""

import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_encryption_keys():
    """
    Generates a new RSA key pair and saves them to disk.
    """

    print("[Tallier] Generating encryption keys...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("tallier_private.pem", "wb") as f:
        f.write(pem_private)

    # serialise and save public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("tallier_public.pem", "wb") as f:
        f.write(pem_public)

    print("[Tallier] Finised generating keys")


def decrypt_ballot(private_key, encrypted_ballot):
    """
    Decrypts a single ballot using hybrid decryption (RSA + AES).
    """
    try:
        # extract AES components from the ballot object
        encrypted_aes_key = bytes.fromhex(encrypted_ballot['key'])
        nonce = bytes.fromhex(encrypted_ballot['nonce'])
        ciphertext = bytes.fromhex(encrypted_ballot['ciphertext'])

        # decrypt the AES session key with the Tallier's private RSA key
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # use the now decrypted AES key to decrypt the actual vote
        aesgcm = AESGCM(aes_key)
        decrypted_vote_json = aesgcm.decrypt(nonce, ciphertext, None)
        
        # decode and parse the plaintext
        return json.loads(decrypted_vote_json.decode('utf-8'))

    except Exception as e:
        print(f"Error decrypting ballot: {e}. Skipping ballot.")
        return None

def main_tally():
    """
    Main function which loads all ballots, decrypts using a hybrid scheme and prints the tally
    """
    print("[Tallier] --- Starting Final Tally ---")
    
    # read talliers private RSA key
    try:
        with open("tallier_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
    except FileNotFoundError:
        print("[Tallier] Error: tallier_private.pem not found.")
        return

    # Load the encrypted ballot object from the server
    try:
        with open("ballots.json", "r") as f:
            ballot_box = json.load(f)
    except FileNotFoundError:
        print("[Tallier] Error: ballots.json not found")
        return
    except json.JSONDecodeError:
        print("[Tallier] Error: ballots.json is corrupted")
        return

    print(f"[Tallier] Loaded {len(ballot_box)} encrypted ballots.")
    
    # Decrypt and tally
    final_tally = {'Alice': 0, 'Bob': 0, 'Charlie': 0}

    # counts how many ballots contained unknown candidates/any errors
    spoiled = 0
    
    for ballot in ballot_box:
        decrypted_ballot = decrypt_ballot(private_key, ballot)
        
        if decrypted_ballot and 'vote' in decrypted_ballot:
            choice = decrypted_ballot['vote']
            if choice in final_tally:
                final_tally[choice] += 1
            else:
                print(f"[Tallier] Warning: Received unknown vote '{choice}'.")
                spoiled += 1
        else:
            spoiled += 1
            
    # Print the results
    print("\n--- ELECTION RESULTS ---")
    print("---------------------------------------")
    for candidate, count in final_tally.items():
        print(f"Candidate: {candidate}, votes received: {count}")
    print(f"{spoiled} votes were invalid")
    print("---------------------------------------\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 2 and sys.argv[1] == 'generate':
        generate_encryption_keys()
    elif len(sys.argv) == 2 and sys.argv[1] == 'tally':
        main_tally()
    else:
        print("Usage:")
        print("  python tallier.py generate   (Run this once before the election)")
        print("  python tallier.py tally      (Run this after the election is closed)")