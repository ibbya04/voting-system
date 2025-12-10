from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import threading
from schnorr import schnorr_verify, signature_from_hex

host = "localhost"
port = 5000
PUBLIC_KEY_FILE = "public_keys.json"

def load_public_key(voter_id):
    '''
    Load voter's public ECDSA signing key
    '''
    try:
        with open(PUBLIC_KEY_FILE, "r") as f:
            data = json.load(f)
        
        if voter_id not in data:
            raise KeyError(f"Voter ID '{voter_id}' not found in public key file.")
        
        # lookup public key from json database for a given voter_id
        serialized_public = data[voter_id]

        loaded_public_key = serialization.load_pem_public_key(
            serialized_public.encode(),
        )
        return loaded_public_key
    except FileNotFoundError:
        raise FileNotFoundError(f"'{PUBLIC_KEY_FILE}' does not exist")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in '{PUBLIC_KEY_FILE}': {e}")
    except Exception as e:
        raise RuntimeError(f"Error loading public key for voter {voter_id}: {e}")
    
def verify_admin_signature(self, path):
        '''
        Verifies that a request to the /open or /close endpoint is correctly signed by the admin
        '''

        try:
            with open("admin_public.pem", "rb") as f:
                admin_public_key = serialization.load_pem_public_key(f.read())

                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)
                data = json.loads(body)

                timestamp = data.get("timestamp")
                signature_hex = data.get("signature_hex")
                
                if not timestamp or not signature_hex:
                    return False, "Missing timestamp or signature"
                
                # Check timestamp if within 60 seconds to prevent replay attacks
                if abs(int(time.time()) - int(timestamp)) > 60:
                    return False, "Request expired"
                
                # Verify admin signature
                message = f"{self.path}:{timestamp}"
                signature = signature_from_hex(signature_hex)
                
                if schnorr_verify(admin_public_key, message, signature):
                    print("[Server] Admin signature verification sucessful")
                    return True, "Admin signature successfully verified"
                else:
                    print("[Server] Admin signature verification failed!")
                    return False, "Invalid admin signature"

        except FileNotFoundError:
            return False, "Admin public key not found"
        except Exception as e:
            return False, str(e)

class votingHTTP(BaseHTTPRequestHandler):
    '''
    Custom HTTP request handler class to manage incoming HTTP requests.
    Only verifies who has voted, not which candidate they voted for
    '''
    # Create a threading lock to protect concurrent access to shared data and a simple shared state container with an initial value of CLOSED.
    lock = threading.Lock()
    status = False

    # list of encrypted ballots
    ballot_box = []
    
    # holds who has voted in this election
    voted_list = set()

    def log_message(self, format, *args):
        """Silences the default request logging."""
        return

    def respond(self, status, message):
        """
        Sends a HTTP response to the client.
        """
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if isinstance(message, (dict, list, bool)):
            # convert dict or list to json
            self.wfile.write(json.dumps(message).encode())
        elif isinstance(message, str):
            self.wfile.write(message.encode())
        else:
            self.wfile.write(b"")

    def do_POST(self):
        '''
        Handles POST requests for /open /close, and /vote
        '''
        if self.path in ['/open', '/close']:
            is_valid, error = verify_admin_signature(self, self.path)
        
            if not is_valid:
                self.respond(401, f"[Server] Unauthorized: {error}")
                return
            
            # handle opening the election
            if self.path == '/open':
                with votingHTTP.lock:
                    votingHTTP.status = True
                    
                    # reset voted list and votes for a new election
                    votingHTTP.votes = {'Alice': 0, 'Bob': 0, 'Charlie': 0}
                    votingHTTP.voted_list = set()
                self.respond(200, "[Server] Succesfully opened server for voting and reset vote counts")
                return
            
            # handle closing the election
            elif self.path == '/close':
                with votingHTTP.lock:
                    votingHTTP.status = False
                    try:
                        with open("ballots.json", "w") as f:
                            json.dump(votingHTTP.ballot_box, f, indent=2)
                            self.respond(200, "[Server] Succesfully saved ballots and closed server for voting")
                    except Exception as e:
                        print(f"[Server] Error: Could not save ballots to disk: {e}")
                        self.respond(400, f"[Server] Error: Could not save ballots to disk: {e}")
                return

        # voting logic
        elif self.path != '/vote':
            self.respond(404, f"[Server] POST requests are only allowed to /vote, /close and /open. Path received was {self.path}")
            return
        
        try: 
            # check status
            with votingHTTP.lock:
                if not votingHTTP.status:
                    raise Exception("[Server] Voting is currently closed")

            # parse incoming json payload
            content_length = int(self.headers.get("Content-Length", 0))
            # read that many bytes from the body of the request
            body = self.rfile.read(content_length)

            data = json.loads(body)

            # extract from dictionary
            voter_id = data.get("voter_id")
            encrypted_ballot = data.get("encrypted_ballot")
            signature_hex = data.get("signature_hex")
            
            if not all([voter_id, encrypted_ballot, signature_hex]):
                raise KeyError("[Server] Missing required fields: voter_id, encrypted_ballot, or signature_hex.")

            # loads public key from db file
            # checks if the voter exists before doing an expensive cryptographic signature verification 
            public_key = load_public_key(voter_id)

            # Check if voter has already voted
            with votingHTTP.lock:
                if voter_id in votingHTTP.voted_list:
                    raise Exception(f"[Server] '{voter_id}' has already cast a ballot.")

            ballot_to_encode = json.dumps(encrypted_ballot, sort_keys=True)

            # verify ECDSA signature received
            try:
                signature = signature_from_hex(signature_hex)
                schnorr_verify(public_key, ballot_to_encode, signature)
            except InvalidSignature:
                # catch the failed signatureverification
                raise Exception(f"[Server] InvalidSignature: Signature verification failed for voter '{voter_id}'.")
            except Exception as e:
                # catch other errors
                raise Exception(f"[Server] Signature processing error for voter '{voter_id}': {e}")

            # record vote
            with votingHTTP.lock:
                votingHTTP.ballot_box.append(encrypted_ballot)
                votingHTTP.voted_list.add(voter_id)
            
            print(f"[Server] Successfully received ballot for {voter_id}")
            self.respond(200, "[Server] Vote successfully recorded\n")
            
        except Exception as e:
            error_msg = f"[Server] Error processing request: {type(e).__name__} - {e}"
            print(f"{error_msg}\nSending error to client")
            self.respond(400, error_msg)

    def do_GET(self):
        '''
        Handles GET requests for /results and /status. 
        '''
        if self.path == '/results':
            # only show results if election is closed
            with votingHTTP.lock:
                self.respond(200, votingHTTP.ballot_box)

        elif self.path == '/status':
            # return current election status
            self.respond(200, votingHTTP.status)

        elif self.path == '/':
            self.respond(200, "<h1>Welcome to my voting server</h1><p>Send a GET request to /results to see vote results.</p>")
     
        else:
            # for any other paths
            self.respond(404, "Error 404: Not Found")

        
if __name__ == "__main__":
    server = HTTPServer((host, port), votingHTTP)
    # print(f"Server is listening on http://{host}:{port}")
    server.serve_forever()