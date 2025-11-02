import requests, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Define the base URL of the server
server_url = "http://localhost:8080"

# NEW Step 3: Write a function that takes as input a voter ID and loads the voter's private key from a PEM file.
#   NEW This key is used to sign the vote before submission.
#   NEW The function should return an error if the voter ID is not an eligible voter. 
def read_private_key(voter_id):
    try:
        with open(f"private_key_{voter_id}.pem", "rb") as f:
            serialized_private = f.read()

            # unserialise private key loaded from file
            loaded_private_key = serialization.load_pem_private_key(
                serialized_private,
                password=b'password',
            )
        return loaded_private_key
    except (FileNotFoundError) as e:
        return e

# NEW Step 4: Write a function to sign the vote. 
#   NEW Your function should take as input a private signing key and a candidate, and should return a signature. 
#   NEW Convert signature to hex string for transmission
def sign_vote(private_key, voter_id, chosen_vote):
    message = f"{voter_id}:{chosen_vote}"
    
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

# NEW Step 5: Write a function to get the status of the server.
#   NEW Your function should return the current status, or an error message if the status cannot be retrieved. 
def check_status():
    status_url = server_url + '/status'
    try:
        r = requests.get(status_url, timeout=5)
        
        if r.status_code == 200:
            return True
        return False
    except Exception as e:
        print(f"Error fetching status")

# Step 5: Write a function to send a vote
#   Generate a signature using the signing function in step 4. 
#   Prepare the headers and JSON payload
#   Include voter ID, candidate name, and signature in the payload.
#   Print the payload for testing purposes.
#   Send a POST request to the /vote endpoint and raise an error if the server responds with a failure code (e.g. 400 or 500)
#   Print the server's response (should be a confirmation message)
def send_vote(voter_id, chosen_vote):

    if check_status() is not True:
        print("Voting is closed!")
        return

    with open("public_keys.json", "r") as f:
        data = json.load(f)

        voter_id = int(voter_id)
        candidates = ["Alice", "Bob", "Charlie"]

        # check if candidate name and voter id inputted exist.
        try:
            # index json object to find public key for a given voter id
            serialized_public = data[voter_id][f"public_key_{voter_id}"]
            if chosen_vote not in candidates:
                raise KeyError

        except IndexError:
            print(f"\nERROR - voter id: '{voter_id}' not found in public key file")
            return
        except KeyError:
            print(f"\nERROR - Candidate: '{chosen_vote}' not in list of candidates")
            return

    private_key = read_private_key(voter_id)

    signature = sign_vote(private_key, voter_id, chosen_vote)
    print(signature)

    vote_url = server_url + '/vote'

    payload = json.dumps([{"chosen_vote": chosen_vote}, {"voter_id": voter_id}, {"signature": signature}])

    r = requests.post(vote_url, payload, timeout=5)

    if (r.status_code != 200):
        print(f"\nServer returned error {r.status_code}:")
        print(r.text.strip() or "No error message provided.")
    else:
        print("\nVote sucessfully sent.\nResponse received: " + r.text)

def get_votes():
    '''
    Step 6: Write a function to fetch current vote results
    Send a GET request to the /results endpoint
    Print the vote tally in a readable format
    '''
    if check_status() is True:
        print("Voting is still open!")
        return

    results_url = server_url + '/results'
    response = requests.get(results_url)

    results = response.json()
    sorted_results = dict(sorted(results.items(), key=lambda item: item[1], reverse=True))
    
    print("\n---------------------------------------")
    for candidate in sorted_results:
        print(f"Candidate: {candidate}, votes received: {sorted_results[candidate]}" )
    print("---------------------------------------\n")

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