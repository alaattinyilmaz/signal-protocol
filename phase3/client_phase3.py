# Emir Alaattin Yılmaz - 2021

from client_basics_Phase3 import PseudoSendMsgPH3, reqOTKB, Status, ReqMsg, OTKReg, ResetOTK, SendMsg
# Run "pip install ecpy" if ecpy is not installed
# Run "pip pickle" if pickle is not installed
from random import randint, seed
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
from Crypto.Cipher import AES
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

def OTK_Registration(n, P, KHMAC, i):
    OTKA_Pri, OTKA_Pub = generate_key(n,P)
    OTKA_i_Pub_x_bytes = OTKA_Pub.x.to_bytes((OTKA_Pub.x.bit_length()+7)//8, 'big')
    OTKA_i_Pub_y_bytes = OTKA_Pub.y.to_bytes((OTKA_Pub.y.bit_length()+7)//8, 'big')
    OTKA_i_Pub_x_y_bytes = OTKA_i_Pub_x_bytes + OTKA_i_Pub_y_bytes
    hmaci = HMAC.new(key=KHMAC, msg=OTKA_i_Pub_x_y_bytes, digestmod=SHA256).hexdigest()
    OTKA = {'OTKA_Pri':OTKA_Pri, 'OTKA_Pub_x': OTKA_Pub.x, 'OTKA_Pub_y': OTKA_Pub.y, 'hmaci': hmaci}
    OTKReg(i, OTKA_Pub.x, OTKA_Pub.y, hmaci)
    return OTKA

def download_msgs(NUM_MSGS,curve,h,s):
    received_msgs = dict()
    for i in range(NUM_MSGS):
        IDB, OTK_ID, msg_id, msg, EK_x, EK_y = ReqMsg(h,s)
        rec_msg = {'MSG_ID': msg_id, 'OTK_ID': OTK_ID, 'msg': msg, 'EKB_Pub': Point(EK_x, EK_y, curve)}
        if IDB not in received_msgs:
            received_msgs[IDB] = dict()
            received_msgs[IDB][OTK_ID] = [rec_msg]
        else:
            if(OTK_ID not in received_msgs[IDB]):
                received_msgs[IDB][OTK_ID] = [rec_msg]
            else:
                received_msgs[IDB][OTK_ID].append(rec_msg)
    return received_msgs

def get_decrypted_msgs(received_msgs, OTKAS):
    NONCE_BYTE_LENGTH = 8
    MAC_BYTE_LENGTH = 32

    decrypted_msgs = []
    for sender in received_msgs.keys():
        for OTK_ID in received_msgs[sender].keys():
            # Sorting the messages according to their message id
            received_msgs[sender][OTK_ID] = sorted(received_msgs[sender][OTK_ID], key=lambda d: d['MSG_ID'])
            NUM_MSGS_FROM_SENDER = len(received_msgs[sender][OTK_ID])
            r_msg = received_msgs[sender][OTK_ID][0]

            if(OTK_ID >= 10):
                MSG_OTK_ID = 9
            else:
                MSG_OTK_ID = r_msg['OTK_ID']

            OTKA_Pri = OTKAS[MSG_OTK_ID]['OTKA_Pri']
            EKB_Pub = r_msg['EKB_Pub']

            Ks = calculate_Ks(OTKA_Pri, EKB_Pub)
            KDF_Chain = calculate_KDF_Chain(Ks, NUM_MSGS_FROM_SENDER)

            for i in range(NUM_MSGS_FROM_SENDER):
                msg = received_msgs[sender][OTK_ID][i]['msg']
                msg_bytes = msg.to_bytes((msg.bit_length()+7)//8, 'big')
                nonce = msg_bytes[:NONCE_BYTE_LENGTH]
                ciphertext = msg_bytes[NONCE_BYTE_LENGTH:-MAC_BYTE_LENGTH]
                mac = msg_bytes[-MAC_BYTE_LENGTH:]
                msg_kenc = KDF_Chain[i]['Kenc']
                msg_khmac = KDF_Chain[i]['Khmac']
                hmaci_r_msg = HMAC.new(key=msg_khmac, msg=ciphertext, digestmod=SHA256).digest()

                verification = False
                if(mac == hmaci_r_msg):
                    verification = True
                else:
                    verification = False

                if(verification == False):
                    print("Could not verified!")
                    return

                cipher = AES.new(msg_kenc, AES.MODE_CTR, nonce=nonce)

                try:
                    decmsg = cipher.decrypt(ciphertext).decode("utf-8")
                    d_msg = {'MSG_ID': received_msgs[sender][OTK_ID][i]['MSG_ID'], 'decmsg': decmsg}     
                    decrypted_msgs.append(d_msg)
                except:
                    print("Ciphertext could not be decoded.")
                    pass

    return decrypted_msgs

def main ():
    
    curve = Curve.get_curve('secp256k1')
    n = curve.order
    P = curve.generator
    
    # Getting credentials from phase1 (secretkey and OTKs)
    with open('credentials.pkl', 'rb') as f: 
        credentials = pickle.load(f)
        sA, KHMAC = credentials['sA'], credentials['KHMAC']

    print("Credentials from phase1 and phase2 are loaded: \n secretkey, KHMAC: {},{} \n".format(sA,KHMAC))

    stuID = 19705 
    stuID_bytes = stuID.to_bytes((stuID.bit_length()+7)//8, 'big')
    h, s = sign(stuID_bytes, sA, n, P)

    # Resetting OTKs
    print("Resetting OTKs...")
    ResetOTK(h,s)

    print("Checking the status of the inbox and keys...")
    num_unread_msgs, num_remaining_otks, _status_msg = Status(stuID, h,s)

    print("Creating OTKs starting from index 0...")
    OTK_NUM = 10
    OTKAS = dict()
    for i in range(OTK_NUM):
        OTKA = OTK_Registration(n, P, KHMAC, i)
        OTKAS[i] = OTKA

    #print(OTKAS)
    
    print("Checking the status of the inbox and keys...")
    num_unread_msgs, num_remaining_otks, _status_msg = Status(stuID, h,s)

    print("Telling pseudoclient to send me messages using PseudoSendMsgPH3")
    print("Signing my stuID with my private IK")

    PseudoSendMsgPH3(h,s)

    print("Checking the status of the inbox and keys...")
    num_unread_msgs, num_remaining_otks, _status_msg = Status(stuID, h,s)

    print("\n")

    # Downloading and decrypting messages
    print("Downloading and decrypting messages \n")
    NUM_MSGS = 5
    received_msgs = download_msgs(NUM_MSGS,curve,h,s)
    decrypted_msgs = get_decrypted_msgs(received_msgs, OTKAS)
    print(decrypted_msgs)
    
    print("\n")
    print("Checking the status of the inbox and keys...")
    num_unread_msgs, num_remaining_otks, _status_msg = Status(stuID, h,s)

    # Registration of new OTK
    while(num_remaining_otks < 10):
        largest_key_id = int(_status_msg[-2:])
        print("Registering new OTK since there is place to add")
        OTK_Registration(n, P, KHMAC, largest_key_id+1)
        num_unread_msgs, num_remaining_otks, _status_msg = Status(stuID, h,s)
        print("\n")

    receiverID = 18007
    print("Sending messages to {}".format(receiverID))

    receiverID_bytes = receiverID.to_bytes((receiverID.bit_length()+7)//8, 'big')
    hB, sB = sign(receiverID_bytes, sA, n, P)

    OTK_B_id, OTK_B_x, OTK_B_y = reqOTKB(stuID, receiverID, hB, sB)
    OTK_B = Point(OTK_B_x, OTK_B_y, curve)

    print("Generating Ephemeral key")
    EKA_Pri, EKA_Pub = generate_key(n, P)
    print("EKA_Pri: ", EKA_Pri)

    print("Generating session key and KDF using my EK and my friend's Public OTK/ Phase 3...")
    Ks = calculate_Ks(EKA_Pri, OTK_B)
    NUM_MSGS = len(decrypted_msgs)
    KDF_Chain = calculate_KDF_Chain(Ks, NUM_MSGS)

    for i in range(NUM_MSGS):

        d_msg = decrypted_msgs[i]
        d_msg_bytes = str.encode(d_msg['decmsg'])

        msg_kenc = KDF_Chain[i]['Kenc']
        msg_khmac = KDF_Chain[i]['Khmac']

        cipher = AES.new(msg_kenc, AES.MODE_CTR)
        nonce = cipher.nonce
        
        ciphertext = cipher.encrypt(d_msg_bytes)
        mac = HMAC.new(key=msg_khmac, msg=ciphertext, digestmod=SHA256).digest()
        encrypted_msg = nonce + ciphertext + mac
        encrypted_msg_int = int.from_bytes(encrypted_msg, byteorder='big')
        
        SendMsg(stuID, receiverID, OTK_B_id, d_msg['MSG_ID'], encrypted_msg_int, EKA_Pub.x, EKA_Pub.y)

    print("Checking the status of the inbox and keys...")
    num_unread_msgs, num_remaining_otks, _status_msg = Status(stuID, h, s)

main()