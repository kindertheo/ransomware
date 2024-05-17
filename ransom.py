from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import shutil


# List txt files in current dir and copy them into "files" folder 
current_dir = os.path.dirname(os.path.abspath(__file__))
initial_file = [file for file in os.listdir(current_dir) if '.txt' in file]
dest_path = os.path.join(current_dir, "files")
os.makedirs(dest_path, exist_ok=True)

for file in initial_file:
    shutil.copyfile(os.path.join(current_dir, file), os.path.join(dest_path, file))


def encrypt_file(file_path, password):
    # Generate a random salt
    salt = os.urandom(16)

    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    print(key)

    # Generate random initialization vector
    iv = os.urandom(16)

    # Create Cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Read file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Set the padding
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the data
    with open(file_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)

def decrypt_file(file_path, password):
    # Open file
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    # Generate key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Create Cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove the padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the data
    with open(file_path, 'wb') as f:
        f.write(decrypted_data)


# For each file in the dest path, encrypt then decrypt it
for file in os.listdir(os.path.join(dest_path)):
    f = os.path.join(dest_path, file)
    encrypt_file(f, 'vincentle+bo')
    decrypt_file(f, 'vincentle+bo')