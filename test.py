import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

voter_id = 1

with open("public_keys.json", "r") as f:
    data = json.load(f)
    pub = data[0][f"public_key_{voter_id}"]

print(pub)
