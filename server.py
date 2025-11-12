from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import threading

host = "localhost"
port = 5000
PUBLIC_KEY_FILE = "public_keys.json"

# Step 3: Define a function to load the public key for a given voter ID from the registrar's database.
#   This key is used to verify the signature on the submitted vote.
def load_public_key(voter_id):
    try:
        with open(PUBLIC_KEY_FILE, "r") as f:
            data = json.load(f)

            # lookup public key for a given voter id
            serialized_public = data.get(voter_id)
            
            if not serialized_public:
                print(f"[Server] '{voter_id}' not found in public key file")
                raise KeyError(f"[Server] '{voter_id}' not found in public key file")

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

class votingHTTP(BaseHTTPRequestHandler):
    '''
    Custom HTTP request handler class to manage incoming HTTP requests.
    '''
    # Create a threading lock to protect concurrent access to shared data and a simple shared state container with an initial value of CLOSED.
    lock = threading.Lock()
    status = False

    # dictionary to hold votes
    votes = {'Alice': 0, 'Bob': 0, 'Charlie': 0}
    
    # list of who has voted in this election
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
        if self.path == '/open':
            with votingHTTP.lock:
                votingHTTP.status = True
                
                # reset voted list and votes for a new election
                votingHTTP.votes = {'Alice': 0, 'Bob': 0, 'Charlie': 0}
                votingHTTP.voted_list = set()
            self.respond(200, "[Server] Succesfully opened server for voting and reset vote counts")
            return
        
        elif self.path == '/close':
            with votingHTTP.lock:
                votingHTTP.status = False
            self.respond(200, "[Server] Succesfully closed server for voting")
            return

        # voting logic
        elif self.path != '/vote':
            self.respond(404, f"[Server] POST requests are only allowed to /vote, /close and /open. Path received was {self.path}")
            return
        
        try: 
            # check status
            if not votingHTTP.status:
                raise Exception("[Server] Voting is currently closed")

            content_length = int(self.headers.get("Content-Length"))
            # read that many bytes from the body of the request
            body = self.rfile.read(content_length)

            input = json.loads(body)

            try:
                candidate = input["candidate"]
                voter_id = input["voter_id"]
                signature_hex = input["signature"]
            except KeyError as e:
                raise KeyError(f"[Server] HTTP request body conatains incorreclty formatted data: {e}")

            # Check if voter has already voted
            with votingHTTP.lock:
                if voter_id in votingHTTP.voted_list:
                    raise Exception(f"[Server] '{voter_id}' has already cast a ballot.")

            public_key = load_public_key(voter_id)
    
            # verify ECDSA signature received
            try:
                message = f"{voter_id}:{candidate}"
                public_key.verify(
                    bytes.fromhex(signature_hex),   # convert hex string to bytes
                    message.encode(),              # convert string to bytes
                    ec.ECDSA(hashes.SHA256())
                )
            except InvalidSignature:
                # catch the failed signatureverification
                raise Exception(f"[Server] InvalidSignature: Signature verification failed for voter '{voter_id}'.")
            except Exception as e:
                # catch other errors
                raise Exception(f"[Server] Signature processing error for voter '{voter_id}': {e}")

            # record vote
            with votingHTTP.lock:
                if candidate in votingHTTP.votes:
                    votingHTTP.votes[candidate] += 1
                    votingHTTP.voted_list.add(voter_id)
                    print(f"[Server] {voter_id} has successfully voted for {candidate}")
                    self.respond(200, "[Server] Vote successfully recorded\n")
                else:
                    raise IndexError(f"[Server] No candidate with name {candidate}, please choose from Alice, Bob or Charlie")
            
        except (json.JSONDecodeError, KeyError, TypeError, IndexError, Exception) as e:
            error_msg = f"[Server] Error processing request: {type(e).__name__} - {e}"
            print(f"{error_msg}\nSending error to client")
            self.respond(400, error_msg)

    def do_GET(self):
        '''
        Handles GET requests for /results and /status. 
        '''
        if self.path == '/results':
            # only show results if election is closed
            if votingHTTP.status == True:
                error_msg = f"[Server] Error voting is still open, cannot view results"
                self.respond(403, error_msg)
                return()

            self.respond(200, votingHTTP.votes)

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