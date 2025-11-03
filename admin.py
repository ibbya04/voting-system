# Step 1: Import modules for command-line arguments, JSON handling and HTTP requests.
import json, requests, sys

# Define the server base URL that the script will contact. 
server_url = "http://localhost:5000"


def do_post_server(path):
    '''
    Define a function that takes as input a path and sends an empty post request.
    Define the full URL as the server_url (defined in step 1) and the path input to the function. 
    Create a Request object with method="POST", an empty JSON body, and Content-Type header
    Open the URL and print the parsed JSON response
    In the event of a HTTP Error, attempt to parse and print the JSON error body; otherwise display the HTTP code
    In the event of other exceptions, your function should print a failure message.
    '''
    specific_url = server_url + path
    data = json.dumps([])
    try:
        r = requests.post(specific_url, data, timeout=5)

        if (r.status_code != 200):
            print(f"\nError {r.status_code}: {r.text}")
        else:
            print("\n" + r.text)
    except Exception as e:
        print(e)


def fetch_status():
    '''
    Define a function that fetches the server status.
    Your function should open the /status endpoint and print the parsed JSON response.
    In the event of an exception, your function should print a failure message.
    '''
    status_url = server_url + '/status'
    try:
        r = requests.get(status_url, timeout=5)
        print(f"\nCurrent server status: {r.json()}")
    except Exception as e:
        print(f"\nError fetching status: {e}")


# Step 5: Define a small helper function that tells users how to run the script.
#   It should provide the user with the options to Open, Close or Get the status of the election. 

# Step 6: Your main function should parse command-line arguments and map them to actions.
#   It should accept the commands "open", "close", and "status".
#   For "open" and "close", it should call the function defined in step 2. 
#   For "status", it should call the function defined in step 3. 
#   Your function should be able to handle invalid inputs. 

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python admin.py <open|close|status>")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "open":
        do_post_server("/open")
    elif command == "close":
        do_post_server("/close")
    elif command == "status":
        fetch_status()
    else:
        print("Invalid command. Use: open, close, or status.")
        sys.exit(1)