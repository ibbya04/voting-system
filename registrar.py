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

if __name__ == "__main__":
    print("Registrar Menu")
    
    choice = int(input("How many voters would you like to register: "))
    
    filename_pk = "public_keys.json"

    for i in range(choice):
        public, private = gen_keypair()

        # save public keys to the json file
        # if file already exists, load current keys + append new keys, then write 
        if not os.path.exists(filename_pk):
            with open(filename_pk, "w") as f:
                json.dump([], f)

        with open(filename_pk, "r") as f:
            data = json.load(f)

        data.append({f"public_key_{i}": public.decode()})

        with open(filename_pk, "w") as f:
            json.dump(data, f, indent=4)

        # save private keys to separate files
        filename_sk = f"private_key_{i}.pem"
        with open(filename_sk, "wb") as f:
            f.write(private)
