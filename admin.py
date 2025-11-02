# Step 1: Import modules for command-line arguments, JSON handling and HTTP requests.
import json, requests

# Step 2: Define the server base URL that the script will contact. 
# You should send requests to port 5000 on local host.
server_url = "http://localhost:8080"


# Step 3: Define a function that takes as input a path and sends an empty post request.
#   Define the full URL as the server_url (defined in step 1) and the path input to the function. 
#   Create a Request object with method="POST", an empty JSON body, and Content-Type header
#   Open the URL and print the parsed JSON response
#   In the event of a HTTP Error, attempt to parse and print the JSON error body; otherwise display the HTTP code
#   In the event of other exceptions, your function should print a failure message.

def open_close_server(path):
    specific_url = server_url + path
    data = json.dumps([])
    try:
        r = requests.post(specific_url, data, timeout=5)

        if (r.status_code != 200):
            print(f"Error {r.status_code}: {r.text}")
        else:
            print(r.text)
    except Exception as e:
        print(e)

def open():
    open_url = server_url + '/open'
    data = json.dumps([])
    try:
        r = requests.post(open_url, data, timeout=5)

        if (r.status_code != 200):
            body = r.json
            print(f"Error {r.status_code}: {r.text}")
        else:
            print('Succesfully opened server for voting' + r.text)
    except Exception as e:
        print(e)

def close():
    close_url = server_url + '/close'
    data = json.dumps([])
    try:
        r = requests.post(close_url, data, timeout=5)

        if (r.status_code != 200):
            body = r.json
            print(f"Error {r.status_code}: {r.text}")
        else:
            print('Succesfully closed server for voting' + r.text)
    except Exception as e:
        print(e)

# Step 4: Define a function that fetches the server status.
#   Your function should open the /status endpoint and print the parsed JSON response.
#   In the event of an exception, your function should print a failure message.
def fetch_status():
    status_url = server_url + '/status'
    try:
        r = requests.get(status_url, timeout=5)
        print(r.json())
    except Exception as e:
        print(f"Error fetching status: {e}")


# Step 5: Define a small helper function that tells users how to run the script.
#   It should provide the user with the options to Open, Close or Get the status of the election. 

# Step 6: Your main function should parse command-line arguments and map them to actions.
#   It should accept the commands "open", "close", and "status".
#   For "open" and "close", it should call the function defined in step 2. 
#   For "status", it should call the function defined in step 3. 
#   Your function should be able to handle invalid inputs. 

if __name__ == "__main__":

    print("\nVoting Admin Menu")
    print("Open: Open the vote")
    print("Close: Close the vote")
    print("Status: Check server status")
    
    choice = input("Enter your choice: ")
    
    if choice == 'Open':
        open()
    elif choice == 'Close':
        close()
    elif choice == 'Status':
        fetch_status()
    else:
        print("Invalid choice. Please enter 'Open', 'Close' or 'Status.")