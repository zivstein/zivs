import DH
import rsa_handler as zRSA
import random
import string
from cryptography.hazmat.primitives import serialization


KEY_PATH = r"C:\Users\yairo\PycharmProjects\salt\public_key.pem"


class KeyExchangeEdge:
    def __init__(self):
        # RSA Global public key for main
        self.PUBLIC_KEY_MASTER_GLOBAL = self.load_key()
        # RSA Keys
        self.private_rsa_edge = None
        self.public_rsa_edge = None
        self.public_rsa_main = None
        # Diffie-Hellman Keys
        self.private_key_edge_dh = None
        self.public_key_edge_dh = None
        self.public_key_main_dh = None
        # Stage messages- msgs received from edge
        self.stage_one_msg_main = None
        self.stage_two_msg_main = None
        # Shared-Key
        self.shared_key = None

    def load_key(self):
        with open(KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_public_key(key_file.read())
        return private_key

    def stage_one(self):
        """
        Sends the public_rsa_edge key, without a signature.
        :return stage_one_msg_edge (Bytes): RSA key in bytes
        """
        self.private_rsa_edge, self.public_rsa_edge = zRSA.gen_key_set()
        stage_one_msg_edge = zRSA.public_key_to_bytes(self.public_rsa_edge)

        return stage_one_msg_edge

    def stage_two(self, stage_two_msg_main, dh_signature):
        """
        Gets the public_key_rsa_main as the stage_two_msg_main.
        The dh_signature
        Sends the public_key_edge_dh
        :param stage_two_msg_main (bytes): data from main
        :param dh_signature (bytes): dh_signature from main
        :return stage_two_msg_edge(Bytes)/ False: False if the signature failed. public_key_edge_dh if the signature is good.
        """
        to_verify_sig = (zRSA.public_key_to_bytes(stage_two_msg_main) + zRSA.public_key_to_bytes(self.public_rsa_edge))
        if zRSA.verify_signature(to_verify_sig, self.PUBLIC_KEY_MASTER_GLOBAL, dh_signature, 1.2) is False:
            return False
        self.public_rsa_main = stage_two_msg_main
        self.private_key_edge_dh, self.public_key_edge_dh = DH.gen_key_set()
        stage_two_msg_edge = str(self.public_key_edge_dh).encode()
        return stage_two_msg_edge

    def stage_three(self, stage_three_msg_main):
        """
        Gets the public_key_main_dh, calculates the shared key and saves it.
        sends a random ACK message that will be encrypted and signed with the shared key.
        :param stage_three_msg_main (Bytes): public_key_main_dh
        :return Ack message (Bytes): A random ack message
        :return shared_key (Str): The shared_key
        """
        self.public_key_main_dh = int(stage_three_msg_main.decode())
        self.shared_key = DH.gen_shared_key(self.private_key_edge_dh, self.public_key_main_dh)
        ack = ''.join(random.choice(string.printable) for i in range(128)).encode()
        signature = zRSA.sign_data(ack, self.private_rsa_edge)
        return ack, signature, self.shared_key





