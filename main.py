import gmpy2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Define the message to be encrypted
message = b'flag{This is an example for ISEP 2023}'

# Generate a new RSA key pair
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Save the public key to a file
with open("public.pem", "wb") as f:
    f.write(public_key.export_key())

# Encrypt the message with the public key
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message)

# Write the ciphertext to a file
with open("ciphertext.bin", "wb") as f:
    f.write(ciphertext)

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

    plaintext = None
    if plaintext is None or not plaintext.startswith(b"flag"):
        # factorize the public key
        ...
        if p is None and q is None:
            ...
            plaintext = new_plaintext.decode()
        else:
            ...
            plaintext = cipher.decrypt(ciphertext).decode()

    if plaintext is None:
        print("The public key could not be factored.")
    else:
        print("Flag found:", plaintext)

    # If none of the provided keys worked, try factoring the public key
    if plaintext is None or not plaintext.startswith(b"flag"):
        public_key = RSA.import_key(open("public.pem").read())
        p, q = factorize_RSA(public_key.n)
        if p is None and q is None:
            print("The public key could not be factored.")
            # Generate new private and public key pair
            new_private_key = RSA.generate(bit_length)
            new_public_key = new_private_key.publickey()
            # Encrypt the message with the new public key
            new_cipher = PKCS1_OAEP.new(new_public_key)
            new_ciphertext = new_cipher.encrypt(message)
            # Save the new private key to a file
            with open("new_private.pem", "wb") as f:
                f.write(new_private_key.export_key())
            # Decrypt the message with the new private key
            new_plaintext = PKCS1_OAEP.new(new_private_key).decrypt(new_ciphertext)
            print("Flag found:", new_plaintext.decode())
        else:
            d = inverse(public_key.e, (p - 1) * (q - 1))
            private_key = RSA.construct((public_key.n, public_key.e, d))
            # Create the cipher object and decrypt the message
            cipher = PKCS1_OAEP.new(private_key)
            plaintext = cipher.decrypt(ciphertext)
            print("Flag found:", plaintext.decode())