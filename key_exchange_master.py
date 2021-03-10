import DH
import rsa_handler as zRSA
import random
import string
from cryptography.hazmat.primitives import serialization


KEY_PATH = r"C:\Users\yairo\PycharmProjects\salt\private_key.pem"


class KeyExchangeMain:
    def __init__(self, session_id):
        # RSA global private key for main
        self.PRIVATE_KEY_MASTER_GLOBAL = self.load_key()
        # Session ID
        self.session_id = session_id
        # RSA Keys
        self.private_key_main_session_rsa = None
        self.public_key_main_session_rsa = None
        self.public_key_edge_rsa = None
        # Diffie-Hellman Keys
        self.public_key_main_dh = None
        self.private_key_main_dh = None
        self.public_key_edge_dh = None
        # Stage messages- msgs received from edge
        self.stage_one_msg_edge = None
        self.stage_two_msg_edge = None
        self.stage_three_msg_edge = None
        # Shared-Key
        self.shared_key = None

    def load_key(self):
        with open(KEY_PATH, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
        return private_key

    def stage_one(self, stage_one_msg_edge):
        """
        Saves the msg received from edge as the public_key_edge_rsa and stage_one_msg_edge.
        Generates RSA private and public key for the session and saves them.
        Create a message sending the public_key_main_session_rsa signed with the PRIVATE_KEY_MASTER_GLOBAL
        on stage_one_msg_edge and the stage_one_msg_main (the public session key).
        :param stage_one_msg_edge (Bytes): RSA public key in bytes
        :return stage_one_msg_main (Bytes), signature (Bytes): data, dh-signature
        """
        self.stage_one_msg_edge = zRSA.public_bytes_to_key(stage_one_msg_edge)
        self.public_key_edge_rsa = self.stage_one_msg_edge
        self.private_key_main_session_rsa, self.public_key_main_session_rsa = zRSA.gen_key_set()
        stage_one_msg_main = self.public_key_main_session_rsa
        sign_on = (zRSA.public_key_to_bytes(stage_one_msg_main) + zRSA.public_key_to_bytes(self.stage_one_msg_edge))
        signature = zRSA.sign_data(sign_on, self.PRIVATE_KEY_MASTER_GLOBAL)

        return stage_one_msg_main, signature

    def stage_two(self, stage_two_msg_edge):
        """
        Gets the public_key_edge_dh and saves it.
        Creates a DH key set for main and sends the public_key_main_dh.
        Calculates the shared key and returns it.
        :param stage_two_msg_edge (Bytes): public_key_edge_dh
        :return stage_two_msg_main (Bytes): public_key_main_dh
        :return shared_key: the final shared key
        """
        self.public_key_edge_dh = int(stage_two_msg_edge.decode())
        self.private_key_main_dh, self.public_key_main_dh = DH.gen_key_set()
        self.shared_key = DH.gen_shared_key(self.private_key_main_dh, self.public_key_edge_dh)
        stage_two_msg_main = str(self.public_key_main_dh).encode()
        return stage_two_msg_main, self.shared_key

    def stage_three(self, stage_three_msg_edge, signature):
        """
        Checks the ack signature after decryption.
        If the signature matches, the decryption was successful and the shared key is equal.
        If not, the decryption failed and the shared key is not equal.
        :param stage_three_msg_edge (Bytes): the decrypted ack message
        :param signature (Bytes): The ack signed with the private_edge_rsa_key
        :return bool: True if the shared key is good, False otherwise
        """
        received_ack = stage_three_msg_edge
        if zRSA.verify_signature(received_ack, self.public_key_edge_rsa, signature, 1.3) is False:
            return False
        return True









