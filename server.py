from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import threading

host = "localhost"
port = 5000

# Step 3: Define a function to load the public key for a given voter ID from the registrar's database.
#   This key is used to verify the signature on the submitted vote.
def load_public_key(voter_id):
    voter_id = int(voter_id)
    try:
        with open("public_keys.json", "r") as f:
            data = json.load(f)

            # index json object to find public key for a given voter id
            serialized_public = data[voter_id][f"public_key_{voter_id}"]

            if not serialized_public:
                print(f"{voter_id} not found in public key file")
                raise KeyError(f"{voter_id} not found in public key file")

            loaded_public_key = serialization.load_pem_public_key(
                serialized_public.encode(),
            )
        return loaded_public_key
    except FileNotFoundError:
        raise FileNotFoundError(f"filename does not exist")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in filename: {e}")
    except IndexError as e:
        raise IndexError(f"Missing key for voter_id {voter_id}: {e}")
    except Exception as e:
        raise RuntimeError(f"Error loading public key for voter {voter_id}: {e}")

# Step 4: Define a custom request handler class to manage incoming HTTP requests.
# It should handle POST requests.
class votingHTTP(BaseHTTPRequestHandler):

    # Create a threading lock to protect concurrent access to shared data and a simple shared state container with an initial value of CLOSED.
    # Use a dictionary to store vote counts for each candidate. It should be held in memory and updated as votes are received.
    # Your voting server should accept votes for three candidates: Alice, Bob and Charlie.
    lock = threading.Lock()
    votes = {'Alice': 0, 'Bob': 0, 'Charlie': 0}
    status = False

    def respond(self, status, message):
        """
        Sends a HTTP response to the client.
        It should set the HTTP status code (as input to the function).
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
        Write a function do_POST(self) that:
        Checks that the incoming request contains JSON data. 
        NEW Your function should accept votes only when election is open.
        Extract the candidate name and validate that the candidate is in the allowed list defined in step 3.
        Return an error response if the candidate is not in the allowed list.
        Check for any missing fields in the JSON data. Return an error response if any fields are missing. 
        Verify the signature. 
        If the candidate is in the allowed list, there are no missing fields, and the signature verifies, increment the vote count for that candidate and return a success message.
        '''
        if self.path == '/open':
            with votingHTTP.lock:
                votingHTTP.status = True
            self.respond(200, "Succesfully opened server for voting")
            return
        
        elif self.path == '/close':
            with votingHTTP.lock:
                votingHTTP.status = False
            self.respond(200, "Succesfully closed server for voting")
            return

        elif self.path != '/vote':
            self.respond(404, "POST requests are only allowed to /vote")
            return
        
        try: 
            content_length = int(self.headers.get("Content-Length"))
            # read that many bytes from the body of the request
            body = self.rfile.read(content_length)

            input = json.loads(body)

            # check status
            if not votingHTTP.status:
                raise Exception("Voting is closed")

            try:
                chosen_vote = input[0]["chosen_vote"]
                voter_id = input[1]["voter_id"]
                signature = input[2]["signature"]
            except KeyError:
                raise KeyError("HTTP request body conatains incorreclty formatted data")

            public_key = load_public_key(int(voter_id))
    
            try:
                message = f"{voter_id}:{chosen_vote}"
                public_key.verify(
                    bytes.fromhex(signature),   # convert hex string to bytes
                    message.encode(),              # convert string to bytes
                    ec.ECDSA(hashes.SHA256())
                )
            except Exception:
                raise Exception(f"Signature doesn't match")

            if chosen_vote in votingHTTP.votes:
                votingHTTP.votes[chosen_vote] += 1
                print(f"Candidate: '{chosen_vote}' exists and vote tally has been updated")
                self.respond(200, "Vote successfully recorded\n")
            else:
                raise IndexError(f"No candidate with name {chosen_vote}, please choose from Alice, Bob or Charlie")
            
        except (json.JSONDecodeError, KeyError, TypeError, IndexError, Exception) as e:
            error_msg = f"Error processing request: {type(e).__name__} - {e}"
            print(f"{error_msg}\nSending error to client")
            self.respond(400, error_msg)

    def do_GET(self):
        '''
        Handles GET requests used to retrieve the current vote results. 
        It should check that the request is targeting the /results endpoint and respond with the current vote tally in JSON format.
        '''
        if self.path == '/results':
            if votingHTTP.status == True:
                error_msg = f"Error voting is still open"
                self.respond(400, error_msg)
                return()

            self.respond(200, votingHTTP.votes)

        elif self.path == '/status':
            self.respond(200, votingHTTP.status)

        elif self.path == '/':
            self.respond(200, "<h1>Welcome to my voting server</h1><p>Send a GET request to /results to see vote results.</p>")
     
        else:
            # for any other paths
            self.respond(404, "Error 404: Not Found")

        
# Step 4: Write a function that sets up and runs the HTTP server.
# It should bind to localhost on port 5000.
# It should run until manually stopped. 
if __name__ == "__main__":
    server = HTTPServer((host, port), votingHTTP)
    print(f"Server is listening on http://{host}:{port}")
    server.serve_forever()