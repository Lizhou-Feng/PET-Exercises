#####################################################
# GA17 Privacy Enhancing Technologies -- Lab 04
#
# Zero Knowledge Proofs
#
# Run the tests through:
# $ py.test -v test_file_name.py

###########################
# Group Members: Killian Davitt, Lizhou Feng
###########################

from petlib.ec import EcGroup
from petlib.bn import Bn

from hashlib import sha256
from binascii import hexlify

def setup():
    """ Generates the Cryptosystem Parameters. """
    G = EcGroup(nid=713)
    g = G.hash_to_point(b"g")
    hs = [G.hash_to_point(("h%s" % i).encode("utf8")) for i in range(4)]
    o = G.order()
    return (G, g, hs, o)

def keyGen(params):
   """ Generate a private / public key pair. """
   (G, g, hs, o) = params
   priv = o.random()
   pub = priv * g
   return (priv, pub)

def to_challenge(elements):
    """ Generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)

#####################################################
# TASK 1 -- Prove knowledge of a DH public key's 
#           secret.

def proveKey(params, priv, pub):
    """ Uses the Schnorr non-interactive protocols produce a proof 
        of knowledge of the secret priv such that pub = priv * g.

        Outputs: a proof (c, r)
                 c (a challenge)
                 r (the response)
    """  
    (G, g, hs, o) = params
    
    ## YOUR CODE HERE:
    w = o.random()
    W = w*g
    c=to_challenge([g, W]) 
    r = (w-c*priv)% o
    
    return (c, r)

def verifyKey(params, pub, proof):
    """ Schnorr non-interactive proof verification of knowledge of a a secret.
        Returns a boolean indicating whether the verification was successful.
    """
    (G, g, hs, o) = params
    c, r = proof
    gw_prime  = c * pub + r * g 
   
    return to_challenge([g, gw_prime]) == c

#####################################################
# TASK 2 -- Prove knowledge of a Discrete Log 
#           representation.

def commit(params, secrets):
    """ Produces a commitment C = r * g + Sum xi * hi, 
        where secrets is a list of xi of length 4.
        Returns the commitment (C) and the opening (r).
    """
    assert len(secrets) == 4
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets
    r = o.random()
    C = x0 * h0 + x1 * h1 + x2 * h2 + x3 * h3 + r * g
    return (C, r)

def proveCommitment(params, C, r, secrets):
    """ Prove knowledge of the secrets within a commitment, 
        as well as the opening of the commitment.

        Args: C (the commitment), r (the opening of the 
                commitment), and secrets (a list of secrets).
        Returns: a challenge (c) and a list of responses.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    x0, x1, x2, x3 = secrets

    ## YOUR CODE HERE:
    w0 = o.random()
    w1 = o.random()
    w2 = o.random()
    w3 = o.random()
    wr = o.random()
    
    W = w0*h0+w1*h1+w2*h2+w3*h3+wr*g
    c = to_challenge([g, h0, h1, h2, h3, W])
    
    r0=w0-c*x0
    r1=w1-c*x1
    r2=w2-c*x2
    r3=w3-c*x3
    rr=wr-c*r
    
    responses = (r0,r1,r2,r3,rr)
    
    return (c, responses)

def verifyCommitments(params, C, proof):
    """ Verify a proof of knowledge of the commitment.
        Return a boolean denoting whether the verification succeeded. """
    (G, g, (h0, h1, h2, h3), o) = params
    c, responses = proof
    (r0, r1, r2, r3, rr) = responses

    Cw_prime = c * C + r0 * h0 + r1 * h1 + r2 * h2 + r3 * h3 + rr * g
    c_prime = to_challenge([g, h0, h1, h2, h3, Cw_prime])
    return c_prime == c

#####################################################
# TASK 3 -- Prove Equality of discrete logarithms.
#

def gen2Keys(params):
    """ Generate two related public keys K = x * g and L = x * h0. """
    (G, g, (h0, h1, h2, h3), o) = params
    x = o.random()

    K = x * g
    L = x * h0

    return (x, K, L)    

def proveDLEquality(params, x, K, L):
    """ Generate a ZK proof that two public keys K, L have the same secret private key x, 
        as well as knowledge of this private key. """
    (G, g, (h0, h1, h2, h3), o) = params
    w = o.random()
    Kw = w * g
    Lw = w * h0

    c = to_challenge([g, h0, Kw, Lw])

    r = (w - c * x) % o
    return (c, r)

def verifyDLEquality(params, K, L, proof):
    """ Return whether the verification of equality of two discrete logarithms succeeded. """ 
    (G, g, (h0, h1, h2, h3), o) = params
    c, r = proof

    ## YOUR CODE HERE:
    Kw_prime = c*K+r*g
    Lw_prime = c*L+r*h0
    
    return to_challenge([g,h0,Kw_prime,Lw_prime]) == c

#####################################################
# TASK 4 -- Prove correct encryption and knowledge of 
#           a plaintext.

def encrypt(params, pub, m):
    """ Encrypt a message m under a public key pub. 
        Returns both the randomness and the ciphertext.
    """
    (G, g, (h0, h1, h2, h3), o) = params
    k = o.random()
    return k, (k * g, k * pub + m * h0)

def proveEnc(params, pub, Ciphertext, k, m):
    """ Prove in ZK that the ciphertext is well formed #jo multiple encryption
        and knowledge of the message encrypted as well. #jo equality

        Return the proof: challenge and the responses.
    """ 
    (G, g, (h0, h1, h2, h3), o) = params
    a, b = Ciphertext

    ## YOUR CODE HERE:
    w1 = o.random()
    w2 = o.random()
    
    W1 = w1*g
    W2 = w1*pub+w2*h0

    c = to_challenge([g, h0, pub, W1,W2])
    
    rk = w1-c*k
    rm = w2-c*m
       
    return (c, (rk, rm))

def verifyEnc(params, pub, Ciphertext, proof):
    """ Verify the proof of correct encryption and knowledge of a ciphertext. """
    (G, g, (h0, h1, h2, h3), o) = params
    a, b = Ciphertext    
    (c, (rk, rm)) = proof

    ## YOUR CODE HERE:
    W1 = c*a+rk*g
    W2 = c*b+rk*pub+rm*h0
    
    return to_challenge([g,h0,pub,W1,W2]) == c

#####################################################
# TASK 5 -- Prove a linear relation
#

def relation(params, x1):
    """ Returns a commitment C to x0 and x1, such that x0 = 10 x1 + 20,
        as well as x0, x1 and the commitment opening r. 
    """
    (G, g, (h0, h1, h2, h3), o) = params
    r = o.random()

    x0 = (10 * x1 + 20)
    C = r * g + x1 * h1 + x0 * h0

    return C, x0, x1, r

def prove_x0eq10x1plus20(params, C, x0, x1, r):
    """ Prove C is a commitment to x0 and x1 and that x0 = 10 x1 + 20. """
    (G, g, (h0, h1, h2, h3), o) = params

    ## YOUR CODE HERE:
    
    w1 = o.random()
    wr = o.random()
 
    W = w1*h1+w1*10*h0+wr*g
    c = to_challenge([g, h1, h0, W])
     
    r1 = w1-c*x1
    rr = wr-c*r
   
    return (c, (r1,rr))

def verify_x0eq10x1plus20(params, C, proof):
    """ Verify that proof of knowledge of C and x0 = 10 x1 + 20. """
    (G, g, (h0, h1, h2, h3), o) = params

    ## YOUR CODE HERE:
    c,(r1,rr)=proof 
    W = r1*h1+r1*10*h0+rr*g+c*(C-20*h0)
    
    return  c == to_challenge([g, h1, h0, W])

#####################################################
# TASK 6 -- (OPTIONAL) Prove that a ciphertext is either 0 or 1


def binencrypt(params, pub, m):
    """ Encrypt a binary value m under public key pub """
    assert m in [0, 1]
    (G, g, (h0, h1, h2, h3), o) = params
    
    k = o.random()
    return k, (k * g, k * pub + m * h0)

def provebin(params, pub, Ciphertext, k, m):
    """ Prove a ciphertext is valid and encrypts a binary value either 0 or 1. """
    pass

def verifybin(params, pub, Ciphertext, proof):
    """ verify that proof that a cphertext is a binary value 0 or 1. """
    pass

def test_bin_correct():
    """ Test that a correct proof verifies """
    pass

def test_bin_incorrect():
    """ Prove that incorrect proofs fail. """
    pass

#####################################################
# TASK Q1 - Answer the following question:
#
# The interactive Schnorr protocol (See PETs Slide 8) offers 
# "plausible deniability" when performed with an 
# honest verifier. The transcript of the 3 step interactive 
# protocol could be simulated without knowledge of the secret 
# (see Slide 12). Therefore the verifier cannot use it to prove 
# to a third party that the holder of secret took part in the 
# protocol acting as the prover.
#
# Does "plausible deniability" hold against a dishonest verifier 
# that  deviates from the Schnorr identification protocol? Justify 
# your answer by describing what a dishonest verifier may do.

""" TODO: Your answer here.

Plausible deniability does not hold for verifiers that deviate from the
protocol.
The most important factor to consider is the random challenge being
issued. 

The reason plausible deniability holds for honest verifiers, is that
when a transcript of the protocol is presented to a 3rd party, it is
entirely possible that the transcript was forged by the verifier. 

A valid transcript of the protocol could be forged by:

1. selecting a random r
2. selecting a random c

and then,

3. Computing a W from c and r,
    W = g^r . pub^c
    
if this is done, any verifier will consider the forged transcript
valid. However, since it is known that forgeries are possible, no
third party will believe that this transcript proves anything.

So, with honest verifiers, The Prover can prove to the verifier that
they posses the discrete log secret to a given public key. however,
the verifier then has no ability to prove this to a 3rd party. The
verifier cannot convince a 3rd party that Bob proved this. 

with a dishonest verifier, this can change. All that is necessary is
for the verifier to not produce a random challenge, but instead to
produce a challenge that is dependant on the value of W that the
prover sends initially. If the value of c is dependant on W. Then, it
is far more difficult for a verifier to forge transcripts. Since the
order of steps in forging transcripts requires that c is computed
before w, if c is dependant on w, it negates the possiblity of forged
transcripts.

to be more specific, imagine that the prover sends the initial W to
the verifier. The verifier then computes the challenge as c = H(W)
where H is a collision resistant hash function. The verifier sends
this challenge back to the prover and the protocol completes.

As usual, the verifier has a transcript of this protocol, but this
time, they can convince any 3rd party fully, that Bob did in fact
prove his knowledge of the discrete log secret. A 3rd party can check
that c is indeed the hashed value of W, which means it could not have
been forged. 

Therefore, if a verifier is dishonest, it can mean that plausible
deniability of the schnorr identification protocol does not hold. 

"""

#####################################################
# TASK Q2 - Answer the following question:
#
# Consider the function "prove_something" below, that 
# implements a zero-knowledge proof on commitments KX
# and KY to x and y respectively. Note that the prover
# only knows secret y. What statement is a verifier, 
# given the output of this function, convinced of?
#
# Hint: Look at "test_prove_something" too.

""" TODO: Your answer here. 

The function proves that the prover knows one of the values, either x
or y. With the values c1 and c2, the verifier checks if c1 + c2 =
C. When the verifier checks this, they know that both c1 and c2 are
correct. Normally this would prove the the prover knew both x and y,
but... since c1 + c2 = C. It is also true that if the prover knew one
of either x or y, they could construct the valid value for c1, and
then set c2 to be C-c1. and vice versa. So, this function proves that
the prover either knows at least one of x,y. 

Indeed, we can see in the proving function that the only reason that
the prover can produce a valid c2 is by substracting c1 from c. But
this does not reveal to the verifier whether the prover produced c1
from a secret and subtracted to find c2, or whether the prover
produced c2 from a secret and subtracted to find c1.

"""

def prove_something(params, KX, KY, y):
    (G, g, _, o) = params

    # Simulate proof for KX
    # r = wx - cx => g^w = g^r * KX^c 
    rx = o.random()
    c1 = o.random()
    W_KX = rx * g + c1 * KX

    # Build proof for KY
    wy = o.random()
    W_KY = wy * g
    c = to_challenge([g, KX, KY, W_KX, W_KY])

    # Build so that: c1 + c2 = c (mod o)
    c2 = (c - c1) % o
    ry = ( wy - c2 * y ) % o

    # return proof
    return (c1, c2, rx, ry)

import pytest

def test_prove_something():
    params = setup()
    (G, g, hs, o) = params

    # Commit to x and y
    x = o.random()
    y = o.random()
    KX = x*g
    KY = y*g

    # Pass only y
    (c1, c2, rx, ry) = prove_something(params, KX, KY, y)

    # Verify the proof
    W_KX = rx * g + c1 * KX
    W_KY = ry * g + c2 * KY
    c = to_challenge([g, KX, KY, W_KX, W_KY])
    assert c % o == (c1 + c2) % o

