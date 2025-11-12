import requests, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

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
        print(f"Error: Private key file '{filename}' not found for voter '{voter_id}'.")
        raise FileNotFoundError
    except Exception as e:
        print(f"Error reading private key: {e}")
        return None

def sign_vote(private_key, voter_id, candidate):
    '''
    Signs the vote message, which is made up of (voter_id:candidate)
    '''
    message = f"{voter_id}:{candidate}"
    
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

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
        print(f"Error fetching status {e}")
        return None

def send_vote(voter_id, candidate):
    '''
    Validates, signs, and sends a single vote to the server.
    '''

    status = check_status()
    if status is None:
        print("Could not determine server status. Exiting.")
        return
    if status is not True:
        print("Voting is currently closed.")
        return

    try:
        # client side vote validation
        with open(PUBLIC_KEY_FILE, "r") as f:
            public_key_db = json.load(f)

        candidates = ["Alice", "Bob", "Charlie"]

        # check if candidate and voter id exists
        if candidate not in candidates:
            print(f"Error Candidate: '{candidate}' not in list of candidates.")
            return
        if voter_id not in public_key_db:
            print(f"Error Voter ID: '{voter_id}' not found in public key file.")
            return
            
    except FileNotFoundError:
        print(f"Error Could not find {PUBLIC_KEY_FILE}.")
        return
    except json.JSONDecodeError:
        print(f"Error Could not parse {PUBLIC_KEY_FILE}.")
        return


    private_key = read_private_key(voter_id)
    if private_key is None:
        print("Could not load private key. Exiting.")
        return

    try:
        # sign vote with voters private key
        signature = sign_vote(private_key, voter_id, candidate)

        vote_url = server_url + '/vote'

        payload = {
            "candidate": candidate,
            "voter_id": voter_id,
            "signature": signature
        }

        r = requests.post(vote_url, json=payload, timeout=5)

        if (r.status_code != 200):
            print(f"\nServer returned error {r.status_code}:")
            print(r.text.strip() or "No error message provided.")
        else:
            print("\nVote sucessfully sent.\nResponse received: " + r.text)

    except requests.exceptions.RequestException as e:
        print(f"Error sending vote: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def get_votes():
    '''
    Fetch current vote results and prints the vote tally in a readable format
    '''

    status = check_status()
    if status is None:
        print("Could not determine server status. Exiting.")
        return
    if status is True:
        print("Voting is still open.")
        return

    results_url = server_url + '/results'
    
    # print formatted results tally 
    try:
        response = requests.get(results_url)

        results = response.json()
        sorted_results = dict(sorted(results.items(), key=lambda item: item[1], reverse=True))
    
        print("\n---------------------------------------")
        for candidate in sorted_results:
            print(f"Candidate: {candidate}, votes received: {sorted_results[candidate]}" )
        print("---------------------------------------\n")
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
        print("2. Get vote results")
        print("3. Exit")
        print("4. Check status")

        choice = input("Enter your choice (1-4): ")
        
        if choice == '1':
            voter_id = input("Enter the voter ID: ")
            candidate = input("Enter the candidate's name (Alice, Bob, or Charlie): ")
            send_vote(voter_id, candidate)
        elif choice == '2':
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