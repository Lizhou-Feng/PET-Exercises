#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 03
#
# Basics of Privacy Friendly Computations through
#         Additive Homomorphic Encryption.
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Setup, key derivation, log
#           Encryption and Decryption
#

###########################
# Group Members: Kam Leung Felix Chiu and Lizhou Feng 
###########################


from petlib.ec import EcGroup

def setup():
    """Generates the Cryptosystem Parameters."""
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    h = G.hash_to_point(b"h")
    o = G.order()
    return (G, g, h, o)

def keyGen(params):
   """ Generate a private / public key pair """
   (G, g, h, o) = params
  
   priv = 0
   while priv == 0:
       priv = o.random()

   pub = priv*g 
 
   return (priv, pub)

def encrypt(params, pub, m):
    """ Encrypt a message under the public key """
    if not -100 < m < 100:
        raise Exception("Message value to low or high.")

    (G, g, h, o) = params

    k = o.random()
    first = k*g
    second = k*pub + m*h
    c = (first, second)

    return c

def isCiphertext(params, ciphertext):
    """ Check a ciphertext """
    (G, g, h, o) = params
    ret = len(ciphertext) == 2
    a, b = ciphertext
    ret &= G.check_point(a)
    ret &= G.check_point(b)
    return ret

_logh = None
def logh(params, hm):
    """ Compute a discrete log, for small number only """
    global _logh
    (G, g, h, o) = params

    # Initialize the map of logh
    if _logh == None:
        _logh = {}
        for m in range (-1000, 1000):
            _logh[(m * h)] = m

    if hm not in _logh:
        raise Exception("No decryption found.")

    return _logh[hm]

def decrypt(params, priv, ciphertext):
    """ Decrypt a message using the private key """
    assert isCiphertext(params, ciphertext)
    a , b = ciphertext

    hm = b + a.pt_mul(priv.int_neg())

    return logh(params, hm)

#####################################################
# TASK 2 -- Define homomorphic addition and
#           multiplication with a public value
# 

def add(params, pub, c1, c2):
    """ Given two ciphertexts compute the ciphertext of the 
        sum of their plaintexts.
    """
    assert isCiphertext(params, c1)
    assert isCiphertext(params, c2)

    (a1,b1) = c1
    (a2,b2) = c2
    c3 = (a1+a2, b1+b2)

    return c3

def mul(params, pub, c1, alpha):
    """ Given a ciphertext compute the ciphertext of the 
        product of the plaintext time alpha """
    assert isCiphertext(params, c1)

    (a,b) = c1
    c3 = (a.pt_mul(alpha), b.pt_mul(alpha))

    return c3

#####################################################
# TASK 3 -- Define Group key derivation & Threshold
#           decryption. Assume an honest but curious 
#           set of authorities.

def groupKey(params, pubKeys=[]):
    """ Generate a group public key from a list of public keys """
    (G, g, h, o) = params

    pub = G.sum(pubKeys)

    return pub

def partialDecrypt(params, priv, ciphertext, final=False):
    """ Given a ciphertext and a private key, perform partial decryption. 
        If final is True, then return the plaintext. """
    assert isCiphertext(params, ciphertext)

    (a,b) = ciphertext
    a1 = a
    a = a.pt_mul(priv.int_neg())
    b1 = b+a 

    if final:
        return logh(params, b1)
    else:
        return a1, b1

#####################################################
# TASK 4 -- Actively corrupt final authority, derives
#           a public key with a known private key.
#

def corruptPubKey(params, priv, OtherPubKeys=[]):
    """ Simulate the operation of a corrupt decryption authority. 
        Given a set of public keys from other authorities return a
        public key for the corrupt authority that leads to a group
        public key corresponding to a private key known to the
        corrupt authority. """
    (G, g, h, o) = params
    
    summ = G.sum(OtherPubKeys)
    pub = priv*g - summ

    return pub

#####################################################
# TASK 5 -- Implement operations to support a simple
#           private poll.
#

def encode_vote(params, pub, vote):
    """ Given a vote 0 or 1 encode the vote as two
        ciphertexts representing the count of votes for
        zero and the votes for one."""
    assert vote in [0, 1]

    if vote == 0:
        v0 = encrypt(params, pub, 1)
        v1 = encrypt(params, pub, 0) 
    else:
        v0 = encrypt(params, pub, 0)
        v1 = encrypt(params, pub, 1) 

    return (v0, v1)

def process_votes(params, pub, encrypted_votes):
    """ Given a list of encrypted votes tally them
        to sum votes for zeros and votes for ones. """
    assert isinstance(encrypted_votes, list)
    
    v0CipherSum = encrypted_votes[0][0]
    v1CipherSum = encrypted_votes[0][1]
    for enc_vote in encrypted_votes[1:]:
        (v0,v1) = enc_vote
        v0CipherSum = add(params, pub, v0CipherSum, v0)
        v1CipherSum = add(params, pub, v1CipherSum, v1)

    tv0 = v0CipherSum
    tv1 = v1CipherSum

    return tv0, tv1

def simulate_poll(votes):
    """ Simulates the full process of encrypting votes,
        tallying them, and then decrypting the total. """

    # Generate parameters for the crypto-system
    params = setup()

    # Make keys for 3 authorities
    priv1, pub1 = keyGen(params)
    priv2, pub2 = keyGen(params)
    priv3, pub3 = keyGen(params)
    pub = groupKey(params, [pub1, pub2, pub3])

    # Simulate encrypting votes
    encrypted_votes = []
    for v in votes:
        encrypted_votes.append(encode_vote(params, pub, v))

    # Tally the votes
    total_v0, total_v1 = process_votes(params, pub, encrypted_votes)

    # Simulate threshold decryption
    privs = [priv1, priv2, priv3]
    for priv in privs[:-1]:
        total_v0 = partialDecrypt(params, priv, total_v0)
        total_v1 = partialDecrypt(params, priv, total_v1)

    total_v0 = partialDecrypt(params, privs[-1], total_v0, True)
    total_v1 = partialDecrypt(params, privs[-1], total_v1, True)

    # Return the plaintext values
    return total_v0, total_v1

###########################################################
# TASK Q1 -- Answer questions regarding your implementation
#
# Consider the following game between an adversary A and honest users H1 and H2: 
# 1) H1 picks 3 plaintext integers Pa, Pb, Pc arbitrarily, and encrypts them to the public
#    key of H2 using the scheme you defined in TASK 1.
# 2) H1 provides the ciphertexts Ca, Cb and Cc to H2 who flips a fair coin b.
#    In case b=0 then H2 homomorphically computes C as the encryption of Pa plus Pb.
#    In case b=1 then H2 homomorphically computes C as the encryption of Pb plus Pc.
# 3) H2 provides the adversary A, with Ca, Cb, Cc and C.
#
# What is the advantage of the adversary in guessing b given your implementation of 
# Homomorphic addition? What are the security implications of this?

"""
If the adversary has access to a decryption oracle (e.g. in CCA), they can find the value of b. First they take the negative of Cb (using pt_neg()) and add the negative with C. Now the sum (or difference) would be passed through the decryption oracle to get either a value of Pa or Pc. Then they can find the value of Pa by simply encrypting a known value, add Ca to the encrypted value, and pass it through the decryption oracle again. This would then tell the adversary the value of Pa. So if Pa is equal to the value calculated in the first summation, then b=0 and if not, b=1. This means that our implementation is not secure against adaptive chosen-ciphertext attacks.
"""

###########################################################
# TASK Q2 -- Answer questions regarding your implementation
#
# Given your implementation of the private poll in TASK 5, how
# would a malicious user implement encode_vote to (a) distrupt the
# poll so that it yields no result, or (b) manipulate the poll so 
# that it yields an arbitrary result. Can those malicious actions 
# be detected given your implementation?

"""
(a) The malicious user can contruct a negative number for each choice equal to the total number of votes they expect for that choice and encrypt that number. For example, let there be a poll on user's favourite colour with the choices red and blue. The malicious user can guess how many voted for each choice, and then encrypt a negative number for that choice so the result would be zero. 
  If they are not confident with their guesses, they can randomly encrypt a large negative number. Consequently, in the summation, the number of votes for each choice would be negative. 
  Therefore, these two situations would yield no result.

(b) Similar to (a), the user can encrypt a large negative number for all the other vote choice other than the one they want. Since the user can essentially control how many votes they want to add or take away from each choice, they can choose the result they want.

Our implementation cannot detect these actions since we do not validate the input of the user. In our implementation, we have no way of telling what the user encrypted.
"""
