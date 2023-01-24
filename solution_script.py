from Crypto.PublicKey import RSA
import gmpy2
from Crypto.Cipher import PKCS1_OAEP

# Read the encrypted message from a file
with open("ciphertext.bin", "rb") as f:
    ciphertext = f.read()

# Read the public key from a file
with open("public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

# Try factoring the public key to obtain the private key
p, q = gmpy2.isqrt(public_key.n) + 1, public_key.n // (gmpy2.isqrt(public_key.n) + 1)

# Check if the factoring was successful
if p * q == public_key.n:
    private_key = RSA.construct((public_key.n, public_key.e, gmpy2.invert(public_key.e, (p-1)*(q-1))))
    # Create the cipher object and decrypt the message
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(ciphertext)
    print("Flag:", plaintext.decode())
else:
    print("Error: The public key could not be factored.")



