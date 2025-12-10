# Secure Electronic Voting System

A secure e-voting system implementing hybrid encryption, Schnorr digital signatures, and Shamir threshold secret sharing.

## Prerequisites

- Python 3.8 or higher
- pip package manager

## Installation

1. Clone or extract the voting system files to a directory.

2. Install required dependencies:

```bash
pip install ecpy cryptography requests
```

Or for lab machines:

```bash
pip install -r requirements.txt
```

## Quick Start

Run the complete end-to-end demo:
```bash
python3 voting-system.py
```

This executes the full election lifecycle automatically, requiring no user input.

## Test Script Documentation

The `voting-system.py` script serves as the end-to-end test suite, demonstrating correct system functionality under ideal conditions (well-formed inputs, honest participants).

### What the Test Script Does

The script executes the following sequence:

| Phase | Action | Expected Outcome |
|-------|--------|------------------|
| 1. Key Generation | Tallier generates RSA keypair and Shamir shares | Creates `tallier_public.pem`, `tallier_private.pem`, `trustee_1.share`, `trustee_2.share`, `trustee_3.share`, `shamir_params.json` |
| 2. Voter Registration | Registrar creates 3 test voters | Creates `public_keys.json`, `private_key_0.pem`, `private_key_1.pem`, `private_key_2.pem`, `admin_private.pem`, `admin_public.pem` |
| 3. Server Startup | Launches HTTP server on localhost:5000 | Server responds to `/status` endpoint |
| 4. Election Opening | Admin sends signed `/open` request | Server returns success, voting enabled |
| 5. Vote Casting | Three voters submit ballots | voter_id_0 → Alice, voter_id_1 → Bob, voter_id_2 → Alice |
| 6. Double Vote Test | voter_id_0 attempts second vote | Server rejects with "already cast a ballot" |
| 7. Election Closing | Admin sends signed `/close` request | Server saves `ballots.json`, voting disabled |
| 8. Tallying | Tallier reconstructs key and decrypts | Final tally: Alice=2, Bob=1, Charlie=0 |
| 9. Cleanup | Server process terminated | Clean shutdown |

### Expected Output

A successful test run produces output similar to:

```
Starting Voting System...

Generating Tallier Keys (RSA)...
[Tallier] Generating encryption keys...
[Tallier] Finished generating keys and distributing private key among 3 trustees.

Registrar starting...
[Registrar] Successfully registered 3 voters to public_keys.json

Starting Voting server (server.py)
Waiting for server to start...
Server started successfully.

Opening election
[Server] Admin signature verification successful
Election is now open.

--- Simulating Votes ---
Casting vote 1 (voter_id_0 -> Alice)...
[Client] Encrypting vote for voter_id_0
[Server] Successfully received ballot for voter_id_0
[Client] Vote successful.

Casting vote 2 (voter_id_1 -> Bob)...
[Client] Vote successful.

Casting vote 3 (voter_id_2 -> Alice)...
[Client] Vote successful.

Casting vote 4 (voter_id_0 -> Bob)... *This should fail*
[Server] Error: 'voter_id_0' has already cast a ballot.

Closing election
[Server] Admin signature verification successful
Election is now closed.

Tallier decrypting and printing results...
[Tallier] Loaded share from trustee 1
[Tallier] Loaded share from trustee 2
[Tallier] Private key successfully reconstructed
[Tallier] Loaded 3 encrypted ballots.

--- ELECTION RESULTS ---
---------------------------------------
Candidate: Alice, votes received: 2
Candidate: Bob, votes received: 1
Candidate: Charlie, votes received: 0
0 votes were invalid
---------------------------------------

Shutting down server
```

### Verification Criteria

The test demonstrates correct functionality when:

1. **All three legitimate votes are accepted** — Server returns 200 for each valid ballot
2. **Double voting is prevented** — Server returns 400 for voter_id_0's second attempt
3. **Signatures are verified** — Admin commands and voter ballots pass cryptographic validation
4. **Encryption works end-to-end** — Tallier successfully decrypts all ballots
5. **Threshold reconstruction succeeds** — Private key recovered from 2 of 3 shares
6. **Tally is correct** — Final count matches votes cast (Alice=2, Bob=1, Charlie=0)
7. **No votes are marked invalid** — Spoiled count is 0

### Running Individual Components

For manual testing or debugging, components can be run separately:

```bash
# Generate tallier keys (run once before election)
python3 tallier.py generate

# Register voters (specify number when prompted)
python3 registrar.py

# Start the voting server
python3 server.py

# Open/close election (in separate terminal)
python3 admin.py open
python3 admin.py close
python3 admin.py status

# Cast votes (interactive mode)
python3 client.py

# Tally results (after election closed)
python3 tallier.py tally
```

### Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `ModuleNotFoundError: ecpy` | Missing dependency | Run `pip install ecpy` |
| `Connection refused` | Server not running | Ensure server.py is running before voting |
| `Admin signature verification failed` | Stale keys | Re-run registrar.py to regenerate admin keys |
| `Private key file not found` | Missing voter keys | Ensure registrar.py completed successfully |
| `Address already in use` | Port 5000 occupied | Kill existing process or wait for timeout |

### Files Generated

After running the test script, the following files are created:

```
├── public_keys.json        # Voter public key database
├── private_key_0.pem       # Voter 0 private key
├── private_key_1.pem       # Voter 1 private key  
├── private_key_2.pem       # Voter 2 private key
├── admin_private.pem       # Administrator private key
├── admin_public.pem        # Administrator public key
├── tallier_private.pem     # Tallier RSA private key (full)
├── tallier_public.pem      # Tallier RSA public key
├── trustee_1.share         # Shamir share for trustee 1
├── trustee_2.share         # Shamir share for trustee 2
├── trustee_3.share         # Shamir share for trustee 3
├── shamir_params.json      # Shamir scheme parameters
└── ballots.json            # Encrypted ballot box (after election closes)
```

## Security Features Demonstrated

- **Hybrid encryption**: AES-256-GCM + RSA-OAEP protects ballot confidentiality
- **Schnorr signatures**: Authenticates voters and prevents ballot tampering
- **Threshold cryptography**: 2-of-3 Shamir scheme prevents premature decryption
- **Replay protection**: Timestamped admin commands with 60-second validity window
- **Double-vote prevention**: Server maintains voted list per election