# Emir Alaattin Yılmaz - 2021

from client_basics_Phase2 import PseudoSendMsg, ReqMsg, Checker
# Run "pip install ecpy" if ecpy is not installed
# Run "pip pickle" if pickle is not installed
from random import randint, seed
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
from Crypto.Cipher import AES
import math
import random
import pickle

random.seed(1453)

# Key Generation
def generate_key(n, P):
    # Secretkey
    sA = random.randint(0, n-1)
    # Public Key
    QA = sA*P
    return sA, QA

# Signature Generation
def sign(m_bytes, sA, n, P):
    k = random.randint(0, n-2)
    R = k*P
    r = R.x % n
    r_bytes = r.to_bytes((r.bit_length()+7)//8, 'big')
    r_II_m = r_bytes+m_bytes
    hashed_rm_bytes = SHA3_256.new(r_II_m)
    h = int.from_bytes(hashed_rm_bytes.digest(), byteorder='big') % n
    s = (k - sA*h) % n
    return h, s

# Calculating Session Key Ks
def calculate_Ks(OTKA_Pri, EKB_Pub):
    T = OTKA_Pri*EKB_Pub
    T_x_bytes = T.x.to_bytes((T.x.bit_length()+7)//8, 'big')
    T_y_bytes = T.y.to_bytes((T.y.bit_length()+7)//8, 'big')
    U = T_x_bytes + T_y_bytes + b'MadMadWorld'
    Ks = SHA3_256.new(U).digest()
    print("T: {}, {}".format(T_x_bytes,T_y_bytes))
    print("U: {}".format(U))
    print("Ks: {} \n".format(Ks))
    return Ks

# KDF Chain
def calculate_KDF_Chain(Ks,NUM_MSGS):
    KDF = Ks
    KDF_chain = []
    for i in range(NUM_MSGS):
        Kenc = SHA3_256.new(KDF + b'LeaveMeAlone').digest()
        Khmac = SHA3_256.new(Kenc + b'GlovesAndSteeringWheel').digest()
        KDF_chain.append({'Kenc':Kenc,'Khmac':Khmac})
        KDF_next = SHA3_256.new(Khmac + b'YouWillNotHaveTheDrink').digest()
        KDF = KDF_next
        print("Kenc{}:, {}".format(i+1,Kenc))
        print("Khmac{}:, {}".format(i+1,Khmac))
        print("KKDF{}:, {} \n".format(i+1,KDF_next))
    return KDF_chain

def main ():
    
    curve = Curve.get_curve('secp256k1')
    n = curve.order
    P = curve.generator
    
    # Getting credentials from phase1 (secretkey and OTKs)
    with open('credentials.pkl', 'rb') as f: 
        credentials = pickle.load(f)
        sA, OTKAS = credentials['sA'], credentials['OTKAS']
    
    print("Credentials from phase1 is loaded: \n secretkey: {},\n OTKAS: {} \n".format(sA,OTKAS))

    stuID = 19705 
    stuID_bytes = stuID.to_bytes((stuID.bit_length()+7)//8, 'big')
    h, s = sign(stuID_bytes, sA, n, P)
    
    print("Telling pseudoclient to send me messages using PseudoSendMsg")
    print("Signing my stuID with my private IK")
    PseudoSendMsg(h,s)
    
    print("\n")

    # Downloading Messages
    NUM_MSGS = 5
    #msgs = [0 for k in range(NUM_MSGS)]
    received_msgs = dict()

    print("Downloading messages \n")
    for i in range(NUM_MSGS):
        IDB, OTK_ID, msg_id, msg, EK_x, EK_y = ReqMsg(h,s)
        rec_msg = {'MSG_ID': msg_id, 'OTK_ID': OTK_ID, 'msg': msg, 'EKB_Pub': Point(EK_x, EK_y, curve)}

        if IDB not in received_msgs:
            received_msgs[IDB] = [rec_msg]
        else:
            received_msgs[IDB].append(rec_msg)

        print("\n")

    NONCE_BYTE_LENGTH = 8
    MAC_BYTE_LENGTH = 32

    for sender in received_msgs.keys():

        # Sorting the messages according to their message id
        received_msgs[sender] = sorted(received_msgs[sender], key=lambda d: d['MSG_ID'])
        NUM_MSGS_FROM_SENDER = len(received_msgs[sender])

        r_msg = received_msgs[sender][0]
        OTKA_Pri = OTKAS[r_msg['OTK_ID']]['OTKA_Pri']
        EKB_Pub = r_msg['EKB_Pub']
        
        Ks = calculate_Ks(OTKA_Pri, EKB_Pub)
        KDF_Chain = calculate_KDF_Chain(Ks,NUM_MSGS_FROM_SENDER)

        for i in range(NUM_MSGS_FROM_SENDER):
            msg = received_msgs[sender][i]['msg']
            msg_bytes = msg.to_bytes((msg.bit_length()+7)//8, 'big')
            
            print("Message {} in byte format: \n {}".format(received_msgs[sender][i]['MSG_ID'], msg_bytes))

            nonce = msg_bytes[:NONCE_BYTE_LENGTH]
            ciphertext = msg_bytes[NONCE_BYTE_LENGTH:-MAC_BYTE_LENGTH]
            mac = msg_bytes[-MAC_BYTE_LENGTH:]
            
            msg_kenc = KDF_Chain[i]['Kenc']
            msg_khmac = KDF_Chain[i]['Khmac']

            hmaci_r_msg = HMAC.new(key=msg_khmac, msg=ciphertext, digestmod=SHA256).digest()
            print("Calculated HMAC: {}".format(hmaci_r_msg))

            verification = False
            if(mac == hmaci_r_msg):
                verification = True
                print("HMAC is verified!")
            else:
                verification = False
                print("HMAC could not be verified!")

            cipher = AES.new(msg_kenc, AES.MODE_CTR, nonce=nonce)

            print("Decrypting the message with AES...")
            try:
                decmsg = cipher.decrypt(ciphertext).decode("utf-8") 
                print("Plaintext: {}".format(decmsg))
            except:
                print("Ciphertext could not be decoded.")
                pass

            if(verification):
                Checker(stuID, sender, received_msgs[sender][i]['MSG_ID'], decmsg)
            else:
                Checker(stuID, sender, received_msgs[sender][i]['MSG_ID'], "INVALIDHMAC")
            print("\n")

main()