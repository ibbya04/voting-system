import random
from typing import List, Tuple

# custom type for a share
Share = Tuple[int, int]

# The following function finds a prime that is greater than or equal to some target value. 
def is_probable_prime(n: int, rounds: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


# This function will test odd numbers to find a prime.
# You can use it to pick a prime for Shamir secrey sharing that is greater than the secret key. 
def next_probable_prime_at_least(m: int) -> int:
    candidate = m if m % 2 == 1 else m + 1
    while not is_probable_prime(candidate):
        candidate += 2
    return candidate


def eval_polynomial(coeffs: List, x: int, p: int):
    '''
    e.g.
    if f(x) = 5 + 2x + 3x^2
    coeffs = [5, 2, 3]
    and if we want to evaluate for x = 2, we want to solve the equation to get f(2) = result
    '''
    result = 0

    # power is evaluating the x^... so at first, 2^0 = 1, then 2^1 = 2 (x^1), then 2^2 = 4 (x^2)
    power = 2**0

    for c in coeffs:
        result = (result + c*power) % p
        power = (power * x) % p

    return result


def generate_shares(secret: int, num_shares: int, threshold: int, p: int) -> List[Share]:

    if secret >= p:
        raise ValueError("Secret cannot be bigger than prime p")
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed num shares")

    coeffs = []
    coeffs.append(secret)

    for _ in range(1, threshold):
        coeffs.append(random.randint(0, p-1))

    shares = []
    for x in range(1, num_shares + 1):
        y = eval_polynomial(coeffs, x, p)
        shares.append((x, y))

    return shares


def lagrange_interpolate_at_zero(x_s: List[int], y_s: List[int], prime: int) -> int:
    assert len(x_s) == len(y_s)
    k = len(x_s)
    total = 0
    for j in range(k):
        xj, yj = x_s[j], y_s[j]
        num = 1
        den = 1
        for m in range(k):
            if m == j:
                continue
            xm = x_s[m]
            num = (num * (-xm)) % prime      
            den = (den * (xj - xm)) % prime
        inv_den = pow(den, -1, prime)
        lj = (num * inv_den) % prime
        total = (total + yj * lj) % prime
    return total


def reconstruct(shares: List, p: int):
    if not shares:
        raise ValueError("No shares given")
    
    x_s, y_s = zip(*shares)

    secret = lagrange_interpolate_at_zero(list(x_s), list(y_s), p)
    return secret

if __name__ == "__main__":
    # Demo
    print("=" * 50)
    print("Shamir Secret Sharing Demo")
    print("=" * 50)
    
    prime = 2**127 - 1
    secret = 42
    n = 5
    t = 3
    
    print(f"\nSecret: {secret}")
    print(f"Shares: {n}, Threshold: {t}")
    
    shares = generate_shares(secret, n, t, prime)
    print(f"\nGenerated shares:")
    for i, (idx, val) in enumerate(shares):
        print(f"  Share {idx}: {val}")
    
    # Reconstruct with exactly t shares
    reconstructed = reconstruct(shares[:t], prime)
    print(f"\nReconstructed from first {t} shares: {reconstructed}")
    print(f"Match: {reconstructed == secret}")
    
    # Reconstruct with different t shares
    reconstructed2 = reconstruct(shares[2:2+t], prime)
    print(f"Reconstructed from shares 3-5: {reconstructed2}")
    print(f"Match: {reconstructed2 == secret}")
