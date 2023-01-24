from Crypto.PublicKey import RSA
import gmpy2
from Crypto.Cipher import PKCS1_OAEP

# If none of the provided keys worked, try factoring the public key
if plaintext is None or not plaintext.startswith(b"flag"):
    public_key = RSA.import_key(open("public.pem").read())
    p,q = factorize_RSA(public_key.n)
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
        d = inverse(public_key.e, (p-1)*(q-1))
        private_key = RSA.construct((public_key.n, public_key.e, d))
        # Create the cipher object and decrypt the message
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)
        print("Flag found:", plaintext.decode())
