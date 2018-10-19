#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 02
#
# Basics of Mix networks and Traffic Analysis
#
# Run the tests through:
# $ py.test -v test_file_name.py

#####################################################
# TASK 1 -- Ensure petlib is installed on the System
#           and also pytest. Ensure the Lab Code can 
#           be imported.

##############################################
# Group Members: Alexios Nikas - Lizhou Feng #
##############################################


from collections import namedtuple
from hashlib import sha512
from struct import pack, unpack
from binascii import hexlify

def aes_ctr_enc_dec(key, iv, input):
    """ A helper function that implements AES Counter (CTR) Mode encryption and decryption. 
    Expects a key (16 byte), and IV (16 bytes) and an input plaintext / ciphertext.

    If it is not obvious convince yourself that CTR encryption and decryption are in 
    fact the same operations.
    """
    
    aes = Cipher("AES-128-CTR") 

    enc = aes.enc(key, iv)
    output = enc.update(input)
    output += enc.finalize()

    return output

#####################################################
# TASK 2 -- Build a simple 1-hop mix client.
#
#


## This is the type of messages destined for the one-hop mix
OneHopMixMessage = namedtuple('OneHopMixMessage', ['ec_public_key', 
                                                   'hmac', 
                                                   'address', 
                                                   'message'])

from petlib.ec import EcGroup
from petlib.hmac import Hmac, secure_compare
from petlib.cipher import Cipher

def mix_server_one_hop(private_key, message_list):
    """ Implements the decoding for a simple one-hop mix. 

        Each message is decoded in turn:
        - A shared key is derived from the message public key and the mix private_key.
        - the hmac is checked against all encrypted parts of the message
        - the address and message are decrypted, decoded and returned

    """
    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not len(msg.hmac) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)        
        h.update(msg.address)
        h.update(msg.message)
        expected_mac = h.digest()

        if not secure_compare(msg.hmac, expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the address and the message
        iv = b"\x00"*16

        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        # Decode the address and message
        address_len, address_full = unpack("!H256s", address_plaintext)
        message_len, message_full = unpack("!H1000s", message_plaintext)

        output = (address_full[:address_len], message_full[:message_len])
        out_queue += [output]

    return sorted(out_queue)
        
        
def mix_client_one_hop(public_key, address, message):
    """
    Encode a message to travel through a single mix with a set public key. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'OneHopMixMessage' with four parts: a public key, an hmac (20 bytes),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 
    """

    G = EcGroup()
    assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those as the payload for encryption
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()

    # Compute the shared key
    shared_key = public_key.pt_mul(private_key)
    K = sha512(shared_key.export()).digest() # Securely Hash the key into a short digest.

    # Use different parts of the shared key for different operations
    hmac_key = K[:16]
    address_key = K[16:32]
    message_key = K[32:48]
    iv = b"\x00"*16 # iv = 0x00000000000000000000000000000000

    # Encrypt using AES Counter mode
    address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
    message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)

    # HMAC
    h = Hmac(b"sha512", hmac_key)        
    h.update(address_cipher)
    h.update(message_cipher)
    expected_mac = h.digest()
    expected_mac = expected_mac[:20]

    return OneHopMixMessage(client_public_key, expected_mac, address_cipher, message_cipher)

    

#####################################################
# TASK 3 -- Build a n-hop mix client.
#           Mixes are in a fixed cascade.
#

from petlib.ec import Bn

# This is the type of messages destined for the n-hop mix
NHopMixMessage = namedtuple('NHopMixMessage', ['ec_public_key', 
                                                   'hmacs', 
                                                   'address', 
                                                   'message'])


def mix_server_n_hop(private_key, message_list, final=False):
    """ Decodes a NHopMixMessage message and outputs either messages destined
    to the next mix or a list of tuples (address, message) (if final=True) to be 
    sent to their final recipients.

    Broadly speaking the mix will process each message in turn: 
        - it derives a shared key (using its private_key), 
        - checks the first hmac,
        - decrypts all other parts,
        - either forwards or decodes the message. 
    """

    G = EcGroup()

    out_queue = []

    # Process all messages
    for msg in message_list:

        ## Check elements and lengths
        if not G.check_point(msg.ec_public_key) or \
               not isinstance(msg.hmacs, list) or \
               not len(msg.hmacs[0]) == 20 or \
               not len(msg.address) == 258 or \
               not len(msg.message) == 1002:
           raise Exception("Malformed input message")

        ## First get a shared key
        shared_element = private_key * msg.ec_public_key
        key_material = sha512(shared_element.export()).digest()

        # Use different parts of the shared key for different operations
        hmac_key = key_material[:16]
        address_key = key_material[16:32]
        message_key = key_material[32:48]

        # Extract a blinding factor for the public_key
        blinding_factor = Bn.from_binary(key_material[48:])
        new_ec_public_key = blinding_factor * msg.ec_public_key

        ## Check the HMAC
        h = Hmac(b"sha512", hmac_key)

        for other_mac in msg.hmacs[1:]:
            h.update(other_mac)

        h.update(msg.address)
        h.update(msg.message)

        expected_mac = h.digest()

        if not secure_compare(msg.hmacs[0], expected_mac[:20]):
            raise Exception("HMAC check failure")

        ## Decrypt the hmacs, address and the message
        aes = Cipher("AES-128-CTR") 

        # Decrypt hmacs
        new_hmacs = []
        for i, other_mac in enumerate(msg.hmacs[1:]):
            # Ensure the IV is different for each hmac
            iv = pack("H14s", i, b"\x00"*14)

            hmac_plaintext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
            new_hmacs += [hmac_plaintext]

        # Decrypt address & message
        iv = b"\x00"*16
        
        address_plaintext = aes_ctr_enc_dec(address_key, iv, msg.address)
        message_plaintext = aes_ctr_enc_dec(message_key, iv, msg.message)

        if final:
            # Decode the address and message
            address_len, address_full = unpack("!H256s", address_plaintext)
            message_len, message_full = unpack("!H1000s", message_plaintext)

            out_msg = (address_full[:address_len], message_full[:message_len])
            out_queue += [out_msg]
        else:
            # Pass the new mix message to the next mix
            out_msg = NHopMixMessage(new_ec_public_key, new_hmacs, address_plaintext, message_plaintext)
            out_queue += [out_msg]

    return out_queue


def mix_client_n_hop(public_keys, address, message):
    """
    Encode a message to travel through a sequence of mixes with a sequence public keys. 
    The maximum size of the final address and the message are 256 bytes and 1000 bytes respectively.
    Returns an 'NHopMixMessage' with four parts: a public key, a list of hmacs (20 bytes each),
    an address ciphertext (256 + 2 bytes) and a message ciphertext (1002 bytes). 

    """
    G = EcGroup()
    # assert G.check_point(public_key)
    assert isinstance(address, bytes) and len(address) <= 256
    assert isinstance(message, bytes) and len(message) <= 1000

    # Encode the address and message
    # Use those encoded values as the payload you encrypt!
    address_plaintext = pack("!H256s", len(address), address)
    message_plaintext = pack("!H1000s", len(message), message)

    ## Generate a fresh public key
    private_key = G.order().random()
    client_public_key  = private_key * G.generator()
    
    aes = Cipher("AES-128-CTR")
    hmacs=[]
    shared_key_material=[]
    
    for publickey in public_keys:
       ## Generate the shared key
       shared_element = private_key * publickey
       key_material = sha512(shared_element.export()).digest()
       shared_key_material+=[key_material]
       
       # Extract a blinding factor for the private key, 
       # such that synchronize the private key with the public key of the client
       blinding_factor = Bn.from_binary(key_material[48:])
       private_key= private_key.int_mul(blinding_factor)
       
    for key_material in reversed(shared_key_material):

       # Use different parts of the shared key for different operations
       hmac_key = key_material[:16]
       address_key = key_material[16:32]
       message_key = key_material[32:48]
     
       ## Encrypt the address & message
       iv = b"\x00"*16
       address_cipher = aes_ctr_enc_dec(address_key, iv, address_plaintext)
       message_cipher = aes_ctr_enc_dec(message_key, iv, message_plaintext)
        
       address_plaintext = address_cipher
       message_plaintext = message_cipher
      
      
       ## Generate the hmac
       h = Hmac(b"sha512", hmac_key) 
       for i,other_mac in enumerate(hmacs):
          iv = pack("H14s", i, b"\x00"*14)
          hmac_ciphertext = aes_ctr_enc_dec(hmac_key, iv, other_mac)
          hmacs[i]=hmac_ciphertext
          
          h.update(hmac_ciphertext)
          
       h.update(address_cipher)
       h.update(message_cipher)
       expected_mac = h.digest()
       expected_mac = expected_mac[:20]
       
       hmacs.insert(0,expected_mac)
       
   
    return NHopMixMessage(client_public_key, hmacs, address_cipher, message_cipher)



#####################################################
# TASK 4 -- Statistical Disclosure Attack
#           Given a set of anonymized traces
#           the objective is to output an ordered list
#           of likely `friends` of a target user.

import random

def generate_trace(number_of_users, threshold_size, number_of_rounds, targets_friends):
    """ Generate a simulated trace of traffic. """
    target = 0
    others = range(1, number_of_users)
    all_users = range(number_of_users)

    trace = []
    ## Generate traces in which Alice (user 0) is not sending
    for _ in range(number_of_rounds // 2):
        senders = sorted(random.sample( others, threshold_size))
        receivers = sorted(random.sample( all_users, threshold_size))

        trace += [(senders, receivers)]

    ## Generate traces in which Alice (user 0) is sending
    for _ in range(number_of_rounds // 2):
        senders = sorted([0] + random.sample( others, threshold_size-1))
        # Alice sends to a friend
        friend = random.choice(targets_friends)
        receivers = sorted([friend] + random.sample( all_users, threshold_size-1))

        trace += [(senders, receivers)]

    random.shuffle(trace)
    return trace


from collections import Counter

def analyze_trace(trace, target_number_of_friends, target=0):
    """ 
    Given a trace of traffic, and a given number of friends, 
    return the list of receiver identifiers that are the most likely 
    friends of the target.
    """

    """ Method 1, without using Counter """


    # # Initialization of lists that we're going to use
    # counter_Alice = 100 * [0]
    # counter_others = 100 * [0]
    # delta = 100 * [0]
    # positions = target_number_of_friends * [0]

    # # Count
    # for i in range(0,1000):
    #     if trace[i][0][0] == 0:
    #         for j in range(0,10):
    #             counter_Alice[trace[i][1][j]] += 1
    #     else:
    #         for k in range(0,10):
    #             counter_others[trace[i][1][k]] += 1

    # # Compute delta between receivers
    # for i in range (0,100):
    #     delta[i] = counter_Alice[i] - counter_others[i]

    # # Final result
    # for a in range(0,target_number_of_friends):
    #     positions[a] = delta.index(max(delta))
    #     delta[delta.index(max(delta))] = 0

    # return positions


    """ Method 2,  using Counter """
    
    possible_target_friends=[]
    targets_friends =[]
    
    for i in range(len(trace)):
      if 0 in trace[i][0]:
    #select the traces where Alice is sending, and store the  corresponding receivers in the possible_target_friends.
        possible_target_friends += trace[i][1]

    #convert the possible_target_friends to Counter type, and use .most_common() to get the most frequent receivers with the number of Alice's friends
    possible_target_friends = Counter(possible_target_friends)
    targets = possible_target_friends.most_common(target_number_of_friends)
    
    #targets = [(friend 1, frequence1),(friend 2, frequence2),...,] so only selecting the 'friend identifier' to store.
    for i in range(target_number_of_friends):
       targets_friends.append(targets[i][0]) 
         
    return targets_friends

## TASK Q1 (Question 1): The mix packet format you worked on uses AES-CTR with an IV set to all zeros. 
#                        Explain whether this is a security concern and justify your answer.


"""
There is no security concern when we are using AES-CTR mode with IV = 0.

IV in AES-CTR mode is used to conduct random encryptions under the same key,
and therefore the ciphertexts can be different when encrypting the same
plaintext multiple times. 

However, in our case the key used in AES-CTR mode is generated every single
time, based on the Diffie-Hellman key exchange. This means that the key used in
each encryption will be different and attackers cannot recover it. Because of
this, attackers cannot look up and modify the message, and therefore
confidentiality and integrity are preserved. 
More importantly, when the same message is encrypted multiple times, the
ciphertext will be different. Thus, even without random IV there is no
information leakage. 

Consequently, with the fixed IV, there is no security concern.
"""


## TASK Q2 (Question 2): What assumptions does your implementation of the Statistical Disclosure Attack 
#                        makes about the distribution of traffic from non-target senders to receivers? Is
#                        the correctness of the result returned dependent on this background distribution?

""" 
The initial assumption is that when Alice does not send any messages, the
traffic follows uniform distribution where non-target senders send to any
receivers with equal probability. Therefore when Alice(target) sends her own
messages, the distribution is not uniform anymore.This is because she sends
messages to her friends, who therefore will appear more often. 

Thus, the correctness of the result returned is dependent on how the
distribution approaches uniformity, without target sender. The more the
distribution without target sender diverges from uniformity, the difference
between that and the distribution with the target sender will be smaller, such
that our results become less correct. 
"""
