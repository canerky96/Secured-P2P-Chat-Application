import random
import socket
import struct
import time
import pickle
database = []
import log
LOG = log.getlog()


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
def multiplicative_inverse(a, b):
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a  # Remember original a/b to remove
    ob = b  # negative values from return results
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob  # If neg wrap modulo orignal b
    if ly < 0:
        ly += oa  # If neg wrap modulo orignal a
    # return a , lx, ly  # Return only positive values
    return lx
def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True
def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)
    # Return public and private keypair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))
def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    # Return the array of bytes
    return cipher
def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    # Return the array of bytes as a string
    return ''.join(plain)
def purge(message):
    message = message.decode('utf-8')
    index = message.find('\x00')
    if index != -1:
        return message[0:index]

if __name__ == '__main__':

    p = 13
    q = 19

    public, private = generate_keypair(p, q)
    LOG.info("Public Key was created -> {}".format(public))
    LOG.info("Private Key was created -> {}".format(private))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 5858))
    s.listen(1)
    LOG.info("SERVER IS LISTENING")
    while 1:
        conn, addr = s.accept()
        username = conn.recv(2048)
        user_public = conn.recv(2048)
        temp = user_public
        user_public = pickle.loads(user_public)

        certificate = username.decode('utf-8') + " " + str(user_public[0]) + " " + str(user_public[1])
        certificate = encrypt(private, certificate)

        LOG.info("USERNAME : {} , PUBLIC KEY : {} , CERTIFICATE : {} from [ {} ]".format(username,user_public,certificate,addr))
        database.append((username, user_public, certificate))

        conn.send(pickle.dumps(certificate))
        time.sleep(0.5)
        conn.send(pickle.dumps(public))

        conn.close()
