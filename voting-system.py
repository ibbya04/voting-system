import os
import subprocess
import time
import requests

import registrar, client, admin, server, tallier

SERVER_SCRIPT = "server.py"
ADMIN_SCRIPT = "admin.py"
SERVER_URL = "http://localhost:5000"

INDENT = "  "

def check_server_running():
    print(f"Waiting for server to start...")

    for _ in range(10):
        try:
            requests.get(f"{SERVER_URL}/status", timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    print("Server failed to start.")
    return False

def main():
    try:
        print("Starting Voting System...")

        # starting tallier to gen it public key
        print("\nGenerating Tallier Keys (RSA)...")
        tallier.generate_encryption_keys()
        
        # start registrat
        print("\nRegistrar starting (warning this overwrites any previous key files)")
        num_voters = int(input("How many voters would you like to register: "))
        registrar.main(num_voters)

        # run the server as a non-blocking background process
        print(f"\nStarting Voting server ({SERVER_SCRIPT}) ")
        server_process = subprocess.Popen(["python", SERVER_SCRIPT])

        # Check if server is running 
        if not check_server_running():
            raise RuntimeError("Server process failed to initialize.")
        print("Server started successfully.")
        
        print("\nOpening election ")
        subprocess.run(["python", ADMIN_SCRIPT, "open"], check=True)
        print("Election is now open.\n")

        # 5. Simulate Votes
        print(f"--- Simulating Votes (via client.py functions) ---")
        # Vote 1: voter_id_0 votes for Alice
        print("Casting vote 1 (voter_id_0 -> Alice)...")
        client.send_vote("voter_id_0", "Alice")
        
        # Vote 2: voter_id_1 votes for Bob
        print("\nCasting vote 2 (voter_id_1 -> Bob)...")
        client.send_vote("voter_id_1", "Bob")
        
        # Vote 3: voter_id_2 votes for Alice
        print("\nCasting vote 3 (voter_id_2 -> Alice)...")
        client.send_vote("voter_id_2", "Alice")

        # Vote 4: voter_id_0 tries to vote AGAIN (should fail)
        print("\nCasting vote 4 (voter_id_0 -> Bob)... *This should fail*")
        client.send_vote("voter_id_0", "Bob")
        print("\nVote simulation complete.\n")

        # close election
        print("Closing election")
        subprocess.run(["python", ADMIN_SCRIPT, "close"], check=True)
        print("Election is now closed.\n")

        print("Tallier decrypting and printing results...")
        tallier.main_tally()
        print("Tally complete.\n")
        
    except Exception as e:
        print(f"\n An error occurred {e}")

    finally:
        # shut down server
        if server_process:
            print("Shutting down server")
            server_process.terminate() # send sigterm
            server_process.wait(timeout=5)

if __name__ == "__main__":
    main()