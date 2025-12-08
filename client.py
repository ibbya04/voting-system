import requests, json, os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from schnorr import schnorr_sign, signature_to_hex


# Define the base URL of the server
server_url = "http://localhost:5000"
PUBLIC_KEY_FILE = "public_keys.json"

def read_private_key(voter_id):
    """
    Loads a voter's private key from their PEM file.
    """
    try:
        filename = f"private_key_{voter_id.split('_')[-1]}.pem"
        with open(filename, "rb") as f:
            serialized_private = f.read()

            # unserialise private key loaded from file
            loaded_private_key = serialization.load_pem_private_key(
                serialized_private,
                password=b'password',
            )
        return loaded_private_key
    except (FileNotFoundError) as e:
        print(f"[Client] Error: Private key file '{filename}' not found for voter '{voter_id}'.")
        raise FileNotFoundError
    except Exception as e:
        print(f"[Client] Error reading private key: {e}")
        return None

def check_status():
    '''
    Checks if the election is open or closed.
    '''
    status_url = server_url + '/status'
    try:
        r = requests.get(status_url, timeout=5)
        r.raise_for_status()
        
        if r.json() is True:
            return True
        return False
    except Exception as e:
        print(f"[Client] Error fetching status {e}")
        return None

def encrypt_ballot(tallier_public_key, voter_id, candidate):
    # form plaintext ballot json object
    ballot_plaintext = json.dumps({"vote": candidate, "voter_id": voter_id}).encode('utf-8')

    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12) # 96-bit nonce

    # encrypt ballot object
    ciphertext = aesgcm.encrypt(nonce, ballot_plaintext, None)

    # encrypt AES session key with talliers public RSA key
    encrypted_aes_key = tallier_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "key": encrypted_aes_key.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }

def send_vote(voter_id, candidate):
    '''
    Validates a vote is correctly formed, then encrypts, signs, and sends the vote to the server.
    '''

    status = check_status()
    if status is None:
        print("[Client] Could not determine server status. Exiting.")
        return
    if status is not True:
        print("[Client] Voting is currently closed.")
        return

    try:
        # client side vote validation
        with open(PUBLIC_KEY_FILE, "r") as f:
            public_key_db = json.load(f)

        candidates = ["Alice", "Bob", "Charlie"]

        # check if candidate and voter id exists
        if candidate not in candidates:
            print(f"[Client] Error: Candidate '{candidate}' not in list of candidates.")
            return
        if voter_id not in public_key_db:
            print(f"[Client] Error: Voter ID: '{voter_id}' not found in public key file.")
            return
            
    except FileNotFoundError:
        print(f"[Client] Error Could not find {PUBLIC_KEY_FILE}.")
        return
    except json.JSONDecodeError:
        print(f"[Client] Error Could not parse {PUBLIC_KEY_FILE}.")
        return

    # load voters private signing key
    private_key = read_private_key(voter_id)
    if private_key is None:
        print("[Client] Could not load private key. Exiting.")
        return
    
    # load talliers public RSA encryption key
    try:
        with open("tallier_public.pem", "rb") as f:
            tallier_public_key = serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print("[Client] Error: tallier_public.pem not found. Cannot encrypt vote.")
        return
    
    # encrypt ballot
    print(f"[Client] Encrypting vote for {voter_id}")
    encrypted_ballot = encrypt_ballot(tallier_public_key, voter_id, candidate)


    ballot_to_sign_str = json.dumps(encrypted_ballot, sort_keys=True)

    try:
        # sign ballot with voters private key
        signature = schnorr_sign(private_key, ballot_to_sign_str)
        signature_hex = signature_to_hex(signature)

        vote_url = server_url + '/vote'

        payload = {
            "voter_id": voter_id,
            "encrypted_ballot": encrypted_ballot,
            "signature_hex": signature_hex
        }

        r = requests.post(vote_url, json=payload, timeout=5)

        if (r.status_code != 200):
            print(f"\n[Client] Server returned error {r.status_code}:")
            print(r.text.strip() or "[Client] No error message provided.")
        else:
            print("\n[Client] Vote sucessfull. Response received:\n" + r.text)

    except requests.exceptions.RequestException as e:
        print(f"[Client] Error sending vote: {e}")
    except Exception as e:
        print(f"[Client] An unexpected error occurred: {e}")

def get_votes():
    '''
    Fetches the public, encrypted ballot board - only the tallier can see the votes
    '''

    if check_status() is True:
        print("Voting is still open therefore this ballot board is not final")
        return

    results_url = server_url + '/results'
    
    # print formatted results tally 
    try:
        response = requests.get(results_url)
        results = response.json()

        print(f"Total encrypted ballots recorded: {len(results)}")
        if len(results) > 0:
            print("Showing first ballot for verification:")
            print(json.dumps(results[0], indent=2))
    except Exception as e:
        print(f"error fetching vote results {e}")

if __name__ == "__main__":
    '''
    This lets users type commands to vote or view results
    If the user types a vote command, extract the candidate name and send the vote
    If the user types 'results', fetch and display the current tally
    '''
    while True:
        print("\nVoting Client Menu")
        print("1. Cast a vote")
        # print("2. Get vote results")
        print("3. Exit")
        print("4. Check status")

        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            voter_id = input("Enter the voter ID: ")
            candidate = input("Enter the candidate's name (Alice, Bob, or Charlie): ")
            send_vote(voter_id, candidate)
        # elif choice == '2':
            get_votes()
        elif choice == '3':
            print("\nExiting.")
            break
        elif choice == '4':
            if check_status() is True:
                print("\nVoting is open")
            else:
                print("\nVoting is closed")
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")