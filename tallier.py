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
from shamir import generate_shares, reconstruct, next_probable_prime_at_least

# shamir paramerters
N_TRUSTEES = 3
THRESHOLD = 2 

def generate_encryption_keys():
    """
    Generates a new RSA key pair and then splits into shares using shamir secret sharing
    """

    print("[Tallier] Generating encryption keys...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # write private key in PEM form to disk
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

    # extract private key components
    priv_nums = private_key.private_numbers()
    p = priv_nums.p
    q = priv_nums.q
    d = priv_nums.d  # secret
    e = priv_nums.public_numbers.e
    n = priv_nums.public_numbers.n

    # generate shamir prime
    shamir_prime = next_probable_prime_at_least(d + 1)

    shares = generate_shares(d, N_TRUSTEES, THRESHOLD, shamir_prime)

    for i, (idx, value) in enumerate(shares):
        # create a dict containing each share, its index and the trustees id
        share_data = {
            "trustee_id": i + 1,
            "share_index": idx,
            "share_value": hex(value)
        }
        filename = f"trustee_{i + 1}.share"

        with open(filename, "w") as f:
            json.dump(share_data, f, indent=2)
        print(f"[Tallier] Share {i + 1} saved to {filename}")

    params = {
        "n_trustees": N_TRUSTEES,
        "threshold": THRESHOLD,
        "shamir_prime": hex(shamir_prime),
        "rsa_p": hex(p),         # needed to rebuild RSA key
        "rsa_q": hex(q),         # Needed to rebuild RSA key
        "rsa_e": e,
        "rsa_n": hex(n)
    }

    with open("shamir_params.json", "w") as f:
        json.dump(params, f, indent=2)


    print("[Tallier] Finised generating keys and distributing private key among {N_TRUSTEES} trustees.")

def load_share(trustee_id):
    # Loads a single trustees share from the file

    filename = f"trustee_{trustee_id}.share"

    try:
        with open(filename, "r") as f:
            data = json.load(f)
        
        idx = data["share_index"]
        value = int(data["share_value"], 16)
        return (idx, value)
    
    except FileNotFoundError:
        raise FileNotFoundError(f"[Tallier] Share file '{filename}' not found")
    except (KeyError, json.JSONDecodeError) as e:
        raise ValueError(f"[Tallier] Invalid share file '{filename}': {e}")

def reconstruct_private_key(trustee_ids: list):
    # Reconstructs the RSA private key from trustee shares.

    # load Shamir parameters
    try:
        with open("shamir_params.json", "r") as f:
            params = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError("[Tallier] shamir_params.json not found")
    
    threshold = params["threshold"]
    shamir_prime = int(params["shamir_prime"], 16)
    rsa_p = int(params["rsa_p"], 16)
    rsa_q = int(params["rsa_q"], 16)
    rsa_e = params["rsa_e"]
    rsa_n = int(params["rsa_n"], 16)
    

    if len(trustee_ids) < threshold:
        raise ValueError(f"[Tallier] Need at least {threshold} shares, got {len(trustee_ids)}")
    # reconstruct shares from the user inputted id's
    shares = []
    for trustee_id in trustee_ids:
        share = load_share(trustee_id)
        shares.append(share)
        print(f"[Tallier] Loaded share from trustee {trustee_id}")
    

    d_rec = reconstruct(shares, shamir_prime)

    # The following will rebuild the private key using original p and q plus reconstructed d
    dmp1 = d_rec % (rsa_p - 1)
    dmq1 = d_rec % (rsa_q - 1)
    iqmp = pow(rsa_q, -1, rsa_p)
    
    public_numbers = rsa.RSAPublicNumbers(e=rsa_e, n=rsa_n)
    private_numbers = rsa.RSAPrivateNumbers(
        p=rsa_p,
        q=rsa_q,
        d=d_rec,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=public_numbers
    )
    
    private_key = private_numbers.private_key()
    print("[Tallier] Private key successfully reconstructed")
    
    return private_key

def prompt_share_ids():

    try:
        with open("shamir_params.json", "r") as f:
            params = json.load(f)
        n_trustees = params["n_trustees"]
        threshold = params["threshold"]
    
        print(f"\nAvailable trustees: 1 to {n_trustees}")
        print(f"Minimum required: {threshold}")

        # id_inputted = input("Input the share id's separated by commas (e.g., 1,2): ")
        id_inputted = "1,2"
        print("[Tallier] Used '1,2' as an example input")

        id_inputted = id_inputted.split(',')

        cleaned_ids = []
        for id in id_inputted:
            id = int(id.strip())
            if id < 1 or id > n_trustees:
                print(f"[Error] Invalid trustee ID: {id}")
                continue
            cleaned_ids.append(id)
        
        return cleaned_ids
    
    except FileNotFoundError:
        raise FileNotFoundError("[Tallier] shamir_params.json not found")
    except Exception as e:
        raise e

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

    try:
        trustee_ids = prompt_share_ids()

        private_key = reconstruct_private_key(trustee_ids)
    except Exception as e:
        print(f"[Tallier] Error reconstructing key: {e}")
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