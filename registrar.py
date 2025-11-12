# Step 1: Import helper functions and functions from cryptography.io for cryptographic operations. 
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import json, os

# Step 2: Generate an ECDSA key pair for a given voter ID.
#   The private key is saved locally; the public key is returned for inclusion in the public database.
#   Generate a new ECDSA private key using the SECP256R1 curve
#   Serialize and save the private key to a PEM file (no encryption)
#   Serialize the public key to a PEM string (used by the server for signature verification)
def gen_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'password')
    )

    public_key = private_key.public_key()
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return serialized_public, serialized_private

# Step 3: Define a function main that prompts the user for number of voters and generates key pairs for each.        
#   Ask the user how many voters to register    
#   Load existing public key database if it exists, or start a new one
#   Generate key pairs for each voter and update the public key database
#   Save the updated public key database to disk

def main(num_voters):
    
    public_key_db = {}
    filename_pk = "public_keys.json"

    for i in range(num_voters):
        public, private = gen_keypair()

        voter_id = str(i)

        # save public keys to the public key dictionary object for now
        public_key_db[f"voter_id_{voter_id}"] = public.decode()

        # save private keys to separate files
        filename_sk = f"private_key_{i}.pem"
        with open(filename_sk, "wb") as f:
            f.write(private)

    # write public keys to database file 
    with open(filename_pk, "w") as f:
        json.dump(public_key_db, f, indent=4)

    print(f"Successfully registered {num_voters} voters to {filename_pk} and private_key_N.pem")

if __name__ == "__main__":
    try:
        num = int(input("How many voters would you like to register: "))
        main(num)
    except ValueError:
        print("Please enter a valid number.")