from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import time
import threading
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from schnorr import schnorr_verify, signature_from_hex

host = "localhost"
port = 5000
PUBLIC_KEY_FILE = "public_keys.json"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('voting_server.log'),
    ]
)
logger = logging.getLogger(__name__)

def load_public_key(voter_id):
    '''
    Load voter's public ECDSA signing key
    '''
    try:
        with open(PUBLIC_KEY_FILE, "r") as f:
            data = json.load(f)
        
        if voter_id not in data:
            logger.error(f"Voter ID '{voter_id}' not found in public key file")
            raise KeyError(f"Voter ID '{voter_id}' not found in public key file")
        
        # lookup public key from json database for a given voter_id
        serialized_public = data[voter_id]

        loaded_public_key = serialization.load_pem_public_key(
            serialized_public.encode(),
        )
        logger.info(f"Successfully loaded public key for voter: {voter_id}")
        return loaded_public_key
    
    except FileNotFoundError:
        logger.error(f"'{PUBLIC_KEY_FILE}' does not exist")
        raise FileNotFoundError(f"'{PUBLIC_KEY_FILE}' does not exist")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in '{PUBLIC_KEY_FILE}': {e}")
        raise ValueError(f"Invalid JSON in '{PUBLIC_KEY_FILE}': {e}")
    except Exception as e:
        logger.error(f"Error loading public key for voter {voter_id}: {e}")
        raise RuntimeError(f"Error loading public key for voter {voter_id}: {e}")
    
def verify_admin_signature(self, path):
        '''
        Verifies that a request to the /open or /close endpoint is correctly signed by the admin
        '''

        try:
            logger.info(f"Verifying admin signature for path: {path}")
            with open("admin_public.pem", "rb") as f:
                admin_public_key = serialization.load_pem_public_key(f.read())

                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)
                data = json.loads(body)

                timestamp = data.get("timestamp")
                signature_hex = data.get("signature_hex")
                
                if not timestamp or not signature_hex:
                    logger.warning("Missing timestamp or signature in admin request")
                    return False, "Missing timestamp or signature"
                
                # Check timestamp if within 60 seconds to prevent replay attacks
                if abs(int(time.time()) - int(timestamp)) > 60:
                    logger.warning(f"Admin request expired. Timestamp: {timestamp}")
                    return False, "Request expired"
                
                # Verify admin signature
                message = f"{self.path}:{timestamp}"
                signature = signature_from_hex(signature_hex)
                
                if schnorr_verify(admin_public_key, message, signature):
                    logger.info("Admin signature verification successful")
                    print("[Server] Admin signature verification sucessful")
                    return True, "Admin signature successfully verified"
                else:
                    logger.warning("Admin signature verification failed")
                    print("[Server] Admin signature verification failed!")
                    return False, "Invalid admin signature"

        except FileNotFoundError:
            logger.error("Admin public key file not found")
            return False, "Admin public key not found"
        except Exception as e:
            logger.error(f"Error verifying admin signature: {e}")
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
        """Log HTTP requests with proper formatting."""
        logger.info(f"{self.address_string()} - {format % args}")

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
        logger.info(f"POST request received at {self.path} from {self.client_address[0]}")

        if self.path in ['/open', '/close']:
            is_valid, error = verify_admin_signature(self, self.path)
        
            if not is_valid:
                logger.warning(f"Unauthorized admin request to {self.path}: {error}")
                self.respond(401, f"[Server] Unauthorized: {error}")
                return
            
            # handle opening the election
            if self.path == '/open':
                with votingHTTP.lock:
                    votingHTTP.status = True
                    
                    # reset voted list and votes for a new election
                    votingHTTP.votes = {'Alice': 0, 'Bob': 0, 'Charlie': 0}
                    votingHTTP.voted_list = set()
                logger.info("Election opened successfully. Vote counts reset.")
                self.respond(200, "[Server] Succesfully opened server for voting and reset vote counts")
                return
            
            # handle closing the election
            elif self.path == '/close':
                with votingHTTP.lock:
                    votingHTTP.status = False
                    try:
                        with open("ballots.json", "w") as f:
                            json.dump(votingHTTP.ballot_box, f, indent=2)
                            logger.info(f"Election closed. {len(votingHTTP.ballot_box)} ballots saved to disk.")
                            self.respond(200, "[Server] Succesfully saved ballots and closed server for voting")
                    except Exception as e:
                        logger.error(f"Could not save ballots to disk: {e}")
                        print(f"[Server] Error: Could not save ballots to disk: {e}")
                        self.respond(400, f"[Server] Error: Could not save ballots to disk: {e}")
                return

        # voting logic
        elif self.path != '/vote':
            logger.warning(f"Invalid POST path: {self.path}")
            self.respond(404, f"[Server] POST requests are only allowed to /vote, /close and /open. Path received was {self.path}")
            return
        
        try: 
            # check status
            with votingHTTP.lock:
                if not votingHTTP.status:
                    logger.warning("Vote attempt while voting is closed")
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
                logger.error("Missing required fields in vote request")
                raise KeyError("[Server] Missing required fields: voter_id, encrypted_ballot, or signature_hex.")
            
            logger.info(f"Processing vote from voter: {voter_id}")

            # loads public key from db file
            # checks if the voter exists before doing an expensive cryptographic signature verification 
            public_key = load_public_key(voter_id)

            # Check if voter has already voted
            with votingHTTP.lock:
                if voter_id in votingHTTP.voted_list:
                    logger.warning(f"Duplicate vote attempt by voter: {voter_id}")
                    raise Exception(f"[Server] '{voter_id}' has already cast a ballot.")

            ballot_to_encode = json.dumps(encrypted_ballot, sort_keys=True)

            # verify ECDSA signature received
            try:
                logger.info(f"Verifying signature for voter: {voter_id}")
                signature = signature_from_hex(signature_hex)
                schnorr_verify(public_key, ballot_to_encode, signature)
                logger.info(f"Signature verified successfully for voter: {voter_id}")
            except InvalidSignature:
                # catch the failed signatureverification
                logger.error(f"Signature verification failed for voter: {voter_id}")
                raise Exception(f"[Server] InvalidSignature: Signature verification failed for voter '{voter_id}'.")
            except Exception as e:
                # catch other errors
                logger.error(f"Signature processing error for voter {voter_id}: {e}")
                raise Exception(f"[Server] Signature processing error for voter '{voter_id}': {e}")

            # record vote
            with votingHTTP.lock:
                votingHTTP.ballot_box.append(encrypted_ballot)
                votingHTTP.voted_list.add(voter_id)
            
            logger.info(f"Vote successfully recorded for voter: {voter_id}. Total votes: {len(votingHTTP.ballot_box)}")
            print(f"[Server] Successfully received ballot for {voter_id}")
            self.respond(200, "[Server] Vote successfully recorded\n")
            
        except Exception as e:
            error_msg = f"[Server] Error processing request: {type(e).__name__} - {e}"
            logger.error(f"Error processing vote request: {e}")
            print(f"{error_msg}\nSending error to client")
            self.respond(400, error_msg)

    def do_GET(self):
        '''
        Handles GET requests for /results and /status. 
        '''
        logger.info(f"GET request received at {self.path} from {self.client_address[0]}")

        if self.path == '/results':
            # only show results if election is closed
            with votingHTTP.lock:
                logger.info(f"Results requested. Returning {len(votingHTTP.ballot_box)} ballots.")
                self.respond(200, votingHTTP.ballot_box)

        elif self.path == '/status':
            # return current election status
            status_text = "OPEN" if votingHTTP.status else "CLOSED"
            logger.info(f"Status requested. Current status: {status_text}")
            self.respond(200, votingHTTP.status)

        elif self.path == '/':
            logger.info("Welcome page requested")
            self.respond(200, "<h1>Welcome to my voting server</h1><p>Send a GET request to /results to see vote results.</p>")
     
        else:
            # for any other paths
            self.respond(404, "Error 404: Not Found")

        
if __name__ == "__main__":
    server = HTTPServer((host, port), votingHTTP)
    # print(f"Server is listening on http://{host}:{port}")
    server.serve_forever()