import pyDH


def gen_key_set():
    """
    Generating public and private keys for DH
    :return: private_key, public_key
    """
    private_key = pyDH.DiffieHellman()
    public_key = private_key.gen_public_key()
    return private_key, public_key


def gen_shared_key(private_key, side2_public_key):
    """
    Gets the private_key and the public_key of the other side.
    Calculates the shared_key and returns it.
    :param private_key:
    :param side2_public_key:
    :return:
    """
    shared_key = private_key.gen_shared_key(side2_public_key)
    return shared_key





