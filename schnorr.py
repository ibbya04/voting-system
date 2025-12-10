'''
Signature scheme:
- Key generation: private key x, public key P = x*G

- Sign(message, x):
    1. k = random nonce
    2. R = k*G
    3. e = Hash(R || P || message)
    4. s = k + e*x (mod n)
    5. signature = (R, s)

- Verify(message, signature, P):
    1. e = Hash(R || P || message)
    2. Check: s*G == R + e*P
'''

import os
import hashlib
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from ecpy.curves import Curve,Point

# use secp384r1 from ecpy and derive the order and a generator point
CURVE = Curve.get_curve('secp384r1')

# ------------------------------- NOTE -----------------------------------------
# secp384r1 curve is of order approx. 384 bytes - but when we do sha256 hash its only 256 bits 
# so we need to always combine 2 x sha256 hashes then modulo by the curve order - values such as k need to be uniformly distributed across curves entire range
CURVE_ORDER = CURVE.order

GENERATOR = CURVE.generator

# helper functions
def int_to_bytes(n, length=48):
    return n.to_bytes(length, byteorder='big')

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

# hashes multiple arguments together
def hash_to_scalar(*args):
    hasher = hashlib.sha256()
    for arg in args:
        if isinstance(arg, bytes):
            hasher.update(arg)
        elif isinstance(arg, str):
            hasher.update(arg.encode('utf-8'))
        elif isinstance(arg, int):
            hasher.update(int_to_bytes(arg))
        elif isinstance(arg, Point):
            hasher.update(int_to_bytes(arg.x))
            hasher.update(int_to_bytes(arg.y))
    

    # computes hash
    hash_output = hasher.digest()

    # see note at top
    extended = hashlib.sha256(hash_output + b'\x01').digest()
    combined = hash_output + extended
    
    return bytes_to_int(combined) % CURVE_ORDER



def signature_to_hex(signature):
    """
    Converts a signature dict to a single hex string for transmission.
    Format: R_x (96 chars) || R_y (96 chars) || s (96 chars)
    """
    R_x = signature['R_x'].zfill(96)
    R_y = signature['R_y'].zfill(96)
    s = signature['s'].zfill(96)
    return R_x + R_y + s


def signature_from_hex(hex_string):
    """
    Reconstructs a signature dict from a hex string.
    """
    if len(hex_string) != 288:
        raise ValueError(f"Invalid signature hex length: {len(hex_string)}, expected 288")
    
    return {
        'R_x': hex_string[0:96],
        'R_y': hex_string[96:192],
        's': hex_string[192:288]
    }



def schnorr_sign(private_key, message):
    """
    Creates a Schnorr signature on the given message.
    
    takes;
        private_key - EC private key
        message

    Returns a dict containing the signature components
    """

    # gets secret number from the key
    private_numbers = private_key.private_numbers()
    x = private_numbers.private_value
    
    # Get public key point P = x*G
    public_key = private_key.public_key()
    pub_numbers = public_key.public_numbers()
    P = Point(pub_numbers.x, pub_numbers.y, CURVE)
    
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # k = Hash(private_key || message) - (this is deterministic to prevent attacks)
    k_hash = hashlib.sha256(int_to_bytes(x) + message).digest()
    k_extended = hashlib.sha256(k_hash + b'\x00').digest()

    k = bytes_to_int(k_hash + k_extended) % CURVE_ORDER
    if k == 0:
        k = 1
    
    # Compute commitment R = k*G
    R = CURVE.mul_point(k, GENERATOR)
    
    # Compute challenge e = Hash(R || P || message)
    # e = sha256(R_x || R_y || P_x || P_y || "encrypted_ballot") mod n
    e = hash_to_scalar(R, P, message)
    
    # response s = k + e*x mod n
    s = (k + e * x) % CURVE_ORDER
    
    # return the x and y cords of commitment point and the response s
    # splice the '0x' off the hex strings for transmission
    return {
        'R_x': hex(R.x)[2:],
        'R_y': hex(R.y)[2:],
        's': hex(s)[2:]
    }


def schnorr_verify(public_key, message, signature):
    """
    verifier checks if r = g^s * y^-e
    """
    try:
        R_x = int(signature['R_x'], 16)
        R_y = int(signature['R_y'], 16)
        s = int(signature['s'], 16)
        
        # rreconstruct point R from input
        R = Point(R_x, R_y, CURVE)
        if not CURVE.is_on_curve(R):
            print("[Schnorr] Invalid signature: R not on curve")
            return False
        
        # Verify s is in valid range
        if s <= 0 or s >= CURVE_ORDER:
            print("[Schnorr] Invalid signature: s out of range")
            return False
        
        # Get public key point P
        pub_numbers = public_key.public_numbers()
        P = Point(pub_numbers.x, pub_numbers.y, CURVE)
        
        # Convert message to bytes if needed
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Recompute challenge e = Hash(R || P || message)
        e = hash_to_scalar(R, P, message)
        
        # Verify: s*G == R + e*P
        left_side = CURVE.mul_point(s, GENERATOR)  # s*G
        eP = CURVE.mul_point(e, P)                  # e*P
        right_side = CURVE.add_point(R, eP)         # R + e*P
        
        if left_side.x == right_side.x and left_side.y == right_side.y:
            return True
        else:
            return False
            
    except Exception as e:
        print(f"[Schnorr] Verification error: {e}")
        return False


# ============ Testing ============

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Schnorr Signature Implementation")
    print("=" * 60)
    
    # Generate test key pair
    print("\n[Test] Generating key pair...")
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    
    # Test 1: Valid signature
    print("\n[Test 1] Sign and verify valid message...")
    message = "voter_id_0:encrypted_ballot_data_here"
    signature = schnorr_sign(private_key, message)
    print(f"  Signature R_x: {signature['R_x'][:32]}...")
    print(f"  Signature s:   {signature['s'][:32]}...")
    
    is_valid = schnorr_verify(public_key, message, signature)
    print(f"  Valid: {is_valid}")
    print(f"  Result: {'PASS' if is_valid else 'FAIL'}")
    
    # Test 2: Tampered message should fail
    print("\n[Test 2] Tampered message should fail...")
    tampered_message = "voter_id_0:TAMPERED_ballot_data"
    is_valid_tampered = schnorr_verify(public_key, tampered_message, signature)
    print(f"  Valid: {is_valid_tampered}")
    print(f"  Result: {'PASS' if not is_valid_tampered else 'FAIL'}")
    
    # Test 3: Wrong public key should fail
    print("\n[Test 3] Wrong public key should fail...")
    wrong_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    wrong_public = wrong_private.public_key()
    is_valid_wrong_key = schnorr_verify(wrong_public, message, signature)
    print(f"  Valid: {is_valid_wrong_key}")
    print(f"  Result: {'PASS' if not is_valid_wrong_key else 'FAIL'}")
    
    # Test 4: Tampered signature should fail
    print("\n[Test 4] Tampered signature should fail...")
    tampered_sig = signature.copy()
    original_s = int(tampered_sig['s'], 16)
    tampered_sig['s'] = hex(original_s + 1)[2:]
    is_valid_tampered_sig = schnorr_verify(public_key, message, tampered_sig)
    print(f"  Valid: {is_valid_tampered_sig}")
    print(f"  Result: {'PASS' if not is_valid_tampered_sig else 'FAIL'}")
    
    # Test 5: Hex conversion round-trip
    print("\n[Test 5] Hex conversion round-trip...")
    hex_sig = signature_to_hex(signature)
    recovered_sig = signature_from_hex(hex_sig)
    is_same = (signature['R_x'] == recovered_sig['R_x'].lstrip('0') or 
               signature['R_x'].zfill(96) == recovered_sig['R_x'])
    print(f"  Hex length: {len(hex_sig)}")
    print(f"  Round-trip successful: {recovered_sig['s'] == signature['s'].zfill(96) or recovered_sig['s'].lstrip('0') == signature['s']}")
    
    # Test 6: Deterministic nonce (same message = same signature)
    print("\n[Test 6] Deterministic nonce (same key+message = same signature)...")
    sig1 = schnorr_sign(private_key, message)
    sig2 = schnorr_sign(private_key, message)
    same_sig = sig1['R_x'] == sig2['R_x'] and sig1['s'] == sig2['s']
    print(f"  Same signature: {same_sig}")
    print(f"  Result: {'PASS' if same_sig else 'FAIL'} (deterministic nonce prevents reuse attacks)")
    print("Schnorr Signature Testing Complete")