from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import logging
import os

"""
IMPORTANT NOTE:
On line 55- add file location if program crashes on this line.
"""

def gen_key_set():
    """
    Creates a private and public RSA keys and returns them.
    :return private_key, public_key:
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    return private_key, public_key


def sign_data(data, private_key):
    """
    Signs the hashed data with the private key.
    Hashing with- SHA256
    Adds padding if the data is too short.
    Returns the signature.
    Signature length- 256.
    :param data(Bytes): Data to be signed
    :param private_key: Private key to sign the data with.
    :return signature (Bytes): The signature of the signed data. Length will always be 256.
    """
    signature = private_key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256())
                                                   , salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature


def verify_signature(data, public_key, signature, stage_number):
    """
    Verifies the signature of the data with the public key and the signature.
    If the verification is successful- the program continues.
    If the verification failed- logs the failed attempt in the format-'%(asctime)s-%(name)s-%(levelname)s-%(message)s'
    :param data(Bytes): Data to verify the signature on
    :param public_key: The public key of the signer
    :param signature: The signature sent by the signer
    :return: True if signature matches, False otherwise
    """
    try:
        public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                       salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except:
        logger = logging.getLogger("Stage {}".format(stage_number))
        fh = logging.FileHandler('signature_fail_log.log')
        print(os.getcwd())
        fh.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - Data: %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        logger.error(data)
        return False


def public_key_to_bytes(public_key):
    """
    Public key to bytes.
    :param public_key:
    :return public_key (bytes):
    """
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem


def public_bytes_to_key(public_bytes):
    return serialization.load_pem_public_key(public_bytes)