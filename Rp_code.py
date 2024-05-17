import random
import hashlib
import time
import cProfile

# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    i = 2
    while i*i <= n:
        if n % i == 0:
            return False
        i += 1
    return True

# Function to generate a random prime number of specified bit length
def generate_prime(bits):
    while True:
        prime_candidate = random.getrandbits(bits)
        if is_prime(prime_candidate):
            return prime_candidate

# Function to compute hash
def hash_func(msg):
    h = hashlib.sha256()
    h.update(msg.encode())
    end_time = time.time()
    return int(h.hexdigest(), 16)

def int_to_bytes(i):
    # Convert integer to bytes
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

# Placeholder for encryption function
def encrypt(key, message):

    start_time_encrypt = time.time()
    # Convert integer key to bytes
    key_bytes = int_to_bytes(key)
    
    # Convert message to bytes
    message_bytes = int_to_bytes(message)
    
    # Repeat or extend the key to match the length of the message
    extended_key = key_bytes * (len(message_bytes) // len(key_bytes)) + key_bytes[:len(message_bytes) % len(key_bytes)]
    
    # Perform XOR operation between each byte of the message and the key
    ciphertext = bytes([m ^ k for m, k in zip(message_bytes, extended_key)])
    
    end_time_encrypt = time.time()

    
    print("Time taken for decryption:", end_time_encrypt - start_time_encrypt, "seconds")
    return ciphertext

# Placeholder for decryption function
def decrypt(key, ciphertext):

    start_time_decrypt = time.time()

    # Convert integer key to bytes
    key_bytes = int_to_bytes(key)
    
    # Repeat or extend the key to match the length of the ciphertext
    extended_key = key_bytes * (len(ciphertext) // len(key_bytes)) + key_bytes[:len(ciphertext) % len(key_bytes)]
    
    # Perform XOR operation between each byte of the ciphertext and the key
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, extended_key)])

    end_time_decrypt = time.time()
    print("Time taken for decryption:", end_time_decrypt - start_time_decrypt, "seconds")

    # Convert plaintext bytes back to integer
    return int.from_bytes(plaintext, byteorder='big')

# Parameters
start_time = time.time()
bits = 32  # Reduced bit length for generating primes
p = generate_prime(bits)  # Random prime number p
q = generate_prime(bits)  # Another prime number q where q | (p-1)
N = p * q  # N = pq
g = random.randint(2, N-1)  # Random element in Zp*, with order p
x_a = random.randint(1, N-1)  # Private key of user a
Y_a = pow(g, x_a, p)  # Public key of user a: Y_a = g^x_a mod p
x_b = random.randint(1, N-1)  # Private key of user b
Y_b = pow(g, x_b, p)  # Public key of user b: Y_b = g^x_b mod p
m = 1243 # Example message


print("g=",g)
print("p=",p)
# Select random number t
t = random.randint(1, N)
print("t=",t)

# Time stamp used to mitigate replay attacks
r = pow(g + int(time.time()), t, p) 
print("r=",r)

# Compute S = (t + r*x_a) mod q
S = (t + r * x_a) % q
print("S=",S)

# Compute l = g^S mod p
l = pow(g, S, p)
print("l=",l)

# Compute K = H1(Y_b^x_a mod p || l)
K_input = str(pow(Y_b, x_a, p) or l)
K = hash_func(K_input)
print("K=",K)

print("m=", m)
I=m+l
print("I=", I)
# Encrypt message m using key K
C = encrypt(K, I)
print("C=",C)

J_input = str((r or K or l) % p)
J = hash_func(J_input)
print("J=", J)


# receiver side
K_input = str(pow(Y_a, x_b, p) or l)
K = hash_func(K_input)
print("K receiver side =",K)
print("C=", C)
I=decrypt(K, C)
print("I=",I)

m=I-l
print("m again=", m)

# Compare J with the original J
# As r=(hash_func(str(l*(Y_a^r) % p or m)))
J1_input = str(((hash_func(str(l*(Y_a^r) % p or m))) or K or l) % p)
J1 = hash_func(J_input)
print("J1= ", J1)
if J == J1:
    print("Verification successful. Message stored:", m)
else:
    print("Verification failed. Message dropped.")
    print("Original message was: ", m)

end_time = time.time()

# Calculate elapsed time
elapsed_time = end_time - start_time
print("Execution time:", elapsed_time, "seconds")

