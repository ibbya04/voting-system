import json

PUBLIC_KEY_FILE = "public_keys.json"

with open(PUBLIC_KEY_FILE, "r") as f:
            data = json.load(f)

            print(type(data))

            # lookup public key for a given voter id
            serialized_public = data.get(f"voter_id_{0}")

            print(serialized_public)

