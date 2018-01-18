import pickle, time, threading, socket, random, struct, hashlib, hmac
from Crypto.Cipher import DES
from Crypto import Random
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


global conn,Kc, Ks, Mc, Ms,user1_publickey,user1_certificate,server_publickey,certificate,user1_username
global ownseq, userseq

def register(public):
    global certificate
    global server_publickey

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 5858))

    s.send("fatih".encode('utf-8'))

    time.sleep(0.5)
    s.send(pickle.dumps(public))

    response = s.recv(2048)
    certificate = pickle.loads(response)

    server_publickey = s.recv(2048)
    server_publickey = pickle.loads(server_publickey)

    s.close()


def send_messsage(typ):  # Ks
    global sh
    global conn
    global Kc, Ks, Mc, Ms
    global ownseq, userseq

    while 1:

        if typ == 0:
            sct = sh
            mac = hmac.new(Mc.encode('utf-8') + str(ownseq).encode('utf-8')).hexdigest()
            enc_key = Kc
        elif typ == 1:
            sct = conn
            mac = hmac.new(Ms.encode('utf-8') + str(ownseq).encode('utf-8')).hexdigest()
            enc_key = Ks
        else:
            print("Error")

        message = input("Your Message >> : ")

        if len(message) % 8 != 0:
            toAdd = 8 - len(message) % 8
            for i in range(toAdd):
                message = message + "#"
        LOG.info("\nMessage : {}".format(message))
        iv = Random.get_random_bytes(8)
        des = DES.new(enc_key, DES.MODE_CBC, iv)
        cipher_message = des.encrypt(message)
        LOG.info("Encrypted Message : {}".format(cipher_message))
        mess_iv_mac = cipher_message + "#-#".encode('utf-8') + iv + "#-#".encode('utf-8') + mac.encode('utf-8')
        sct.send(mess_iv_mac)
        ownseq = ownseq + 1
        if message == "QUIT".encode('utf-8'):
            sct.close()
            break

def get_message(typ):
    global sh
    global conn
    global Kc, Ks, Mc, Ms
    global ownseq, userseq

    if typ == 0:
        sct = sh
        mac_key = Ms
        enc_key = Ks
    elif typ == 1:
        sct = conn
        mac_key = Mc
        enc_key = Kc
    else:
        print("Error")

    while 1:
        print("User Seq Number : ", userseq)
        enc_message_iv = sct.recv(2048)
        enc_message, iv, user_mac = enc_message_iv.split("#-#".encode('utf-8'))

        if user_mac.decode('utf-8') == hmac.new(mac_key.encode('utf-8') + str(userseq).encode('utf-8')).hexdigest():
            LOG.info("MACs are equal")

        else:
            LOG.info(" DIFFERENT MAC !!!!")

        userseq = userseq + 1

        des1 = DES.new(enc_key, DES.MODE_CBC, iv)
        LOG.info("Encrypted Message : {}".format(enc_message))
        message = des1.decrypt(enc_message)

        message = message.decode('utf-8')
        message = message.replace("#", "")
        LOG.info("Decrypted Message : {}".format(message))
        time.sleep(0.3)
        print("User2 >>  ", message)
        if message == "QUIT":
            sct.close()
            break


def handler():
    global certificate
    global server_publickey
    global user1_certificate
    global user1_username
    global user1_publickey
    global conn
    global Kc, Ks, Mc, Ms

    sh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sh.bind(('127.0.0.1', 5151))
    sh.listen(1)

    while 1:
        global conn
        global Kc, Ks, Mc, Ms
        conn, addr = sh.accept()

        message = conn.recv(2048)
        user1_certificate = conn.recv(2048)
        user1_certificate = pickle.loads(user1_certificate)

        dec = decrypt(server_publickey, user1_certificate)
        user1_username, key1, key2 = dec.split(" ")
        user1_publickey = (int(key1), int(key2))

        print("User1's message ( {} ): ".format(user1_username), message.decode('utf-8'), "  certificate : ",
              user1_certificate, "  PublicKey : ", user1_publickey)

        nonce = str(random.randint(0, 1000))
        print("Nonce : ", nonce)
        conn.send(nonce.encode('utf-8'))
        time.sleep(0.2)
        conn.send(pickle.dumps(certificate))

        enc_nonce = conn.recv(2048)
        enc_nonce = pickle.loads(enc_nonce)
        enc_nonce = decrypt(user1_publickey, enc_nonce)
        enc_nonce = int(enc_nonce)
        print("Nonce (Encrypted): ", enc_nonce)

        if enc_nonce == int(nonce):
            conn.send("ack".encode('utf-8'))

        master_secret = conn.recv(2048)
        master_secret = master_secret.decode('utf-8')
        print("Master Secret : ", master_secret)

        Kc = master_secret[0:8]
        Mc = master_secret[8:16]
        Ks = master_secret[16:24]
        Ms = master_secret[24:32]

        send_t = threading.Thread(target=send_messsage, args=(1,))
        send_t.start()

        get_t = threading.Thread(target=get_message, args=(1,))
        get_t.start()


def handshake():
    global certificate
    global server_publickey
    global user2_certificate
    global user2_publickey
    global private
    global Kc, Ks, Mc, Ms
    global sh

    sh = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sh.connect(('127.0.0.1', 5151))

    sh.send("hello".encode('utf-8'))
    time.sleep(0.2)
    sh.send(pickle.dumps(certificate))

    nonce = sh.recv(2048)
    nonce = int(nonce.decode('utf-8'))
    print("Nonce : ", nonce)

    user2_certificate = sh.recv(2048)
    user2_certificate = pickle.loads(user2_certificate)
    user2_certificate = decrypt(server_publickey, user2_certificate)

    user2_username, key1, key2 = user2_certificate.split(" ")

    user2_publickey = (int(key1), int(key2))

    print("User2's  ( {} ): ".format(user2_username), "  certificate : ", user2_certificate, "  PublicKey : ",
          user2_publickey)

    enc_nonce = encrypt(private, str(nonce))
    sh.send(pickle.dumps(enc_nonce))

    acknowledge = sh.recv(2048)
    acknowledge = acknowledge.decode('utf-8')

    if acknowledge == 'ack':
        print("Ack recieved")

    master_secret = hashlib.md5()
    master_secret.update(str(nonce).encode('utf-8'))
    master_secret = master_secret.hexdigest()

    sh.send(master_secret.encode('utf-8'))
    print("Master Secret : ", master_secret)

    Kc = master_secret[0:8]
    Mc = master_secret[8:16]
    Ks = master_secret[16:24]
    Ms = master_secret[24:32]

    print(Kc, Mc, Ks, Ms)

    gt = threading.Thread(target=get_message, args=(0,))
    gt.start()

    st = threading.Thread(target=send_messsage, args=(0,))
    st.start()


if __name__ == '__main__':
    global certificate
    global server_publickey
    global user1_username
    global ownseq, userseq
    ownseq = 0
    userseq = 0

    p = 13
    q = 23

    public, private = generate_keypair(p, q)

    LOG.info("Public Key was created -> {}".format(public))
    LOG.info("Private Key was created -> {}".format(private))
    register(public)
    LOG.info("Your Certificate -> {}".format(certificate))
    LOG.info("Server Public Key -> {}".format(server_publickey))

    time.sleep(0.2)

    print("1. HANDSHAKE")
    print("2. LISTEN")
    choice = input("Please make your choice : ")

    if choice == "1":
        handshake()
    elif choice == "2":
        t = threading.Thread(target=handler)
        t.start()
    else:
        print("WRONG CHOICE")