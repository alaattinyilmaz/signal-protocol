# Emir Alaattin Yılmaz - 2021

from client_basics import IKRegReq, IKRegVerify, SPKReg, OTKReg, ResetIK, ResetOTK, ResetSPK
# Run "pip install ecpy" if ecpy is not installed
from random import randint, seed
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, SHA256, HMAC
import math
import random

random.seed(1923)

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

# Signature verification
def signature_verification(m_bytes, h, s, n, QA, P):
    V = s*P + h*QA
    v = V.x % n
    v_bytes = v.to_bytes((v.bit_length()+7)//8, 'big')
    v_II_m = v_bytes + m_bytes
    hashed_vm_bytes = SHA3_256.new(v_II_m).digest()
    h_prime = int.from_bytes(hashed_vm_bytes, byteorder='big') % n
    if(h == h_prime):
        return True
    else:
        return False


def main ():
    curve = Curve.get_curve('secp256k1')
    n = curve.order
    P = curve.generator

    # IK
    sA, QA = generate_key(n,P)

    # Public key
    IKA_Pub = Point(QA.x, QA.y, curve)

    print("IK is created: \n IK.Pri : {} \n IK.Pub : {}".format(sA, IKA_Pub))

    #Server's Identitiy public key
    IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813, 8985629203225767185464920094198364255740987346743912071843303975587695337619, curve)

    stuID = 19705 
    
    print("My ID number is {}".format(stuID))

    stuID_bytes = stuID.to_bytes((stuID.bit_length()+7)//8, 'big')

    print("Converted my ID to bytes in order to sign it: {} \n".format(stuID_bytes))

    h, s = sign(stuID_bytes, sA, n, P)

    print("Signature of my ID number is:\n h = {} \n s = {} \n".format(h,s))
    print("Sending signature and my IKEY to server via IKRegReq() function in json format")

    # Registration of IK
    IKRegReq(h,s,IKA_Pub.x,IKA_Pub.y)

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    print("Received the verification code through email.")

    try:
         # Authentication
        verification_code = int(input("Enter verification code which is sent to you: "))
        print("Sending the verification code to server via IKRegVerify() function in json format")
        IKRegVerify(verification_code)
    except Exception as e:
        print(e)
        return

    # Save the reset code! 
    #rcode = 441705
    #ResetIK(rcode)
    #return

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    # SPK
    print("Generating SPK...\n")

    SPKA_Pri, SPKA_Pub = generate_key(n,P)
    print("Private SPK: {} \n Public SPK.x: {} \n Public SPK.y: {} \n".format(SPKA_Pri,SPKA_Pub.x,SPKA_Pub.y))
    
    SPKA_Pub_x_bytes = SPKA_Pub.x.to_bytes((SPKA_Pub.x.bit_length()+7)//8, 'big')
    SPKA_Pub_y_bytes = SPKA_Pub.y.to_bytes((SPKA_Pub.y.bit_length()+7)//8, 'big')
    SPKA_PUB_x_y_bytes = SPKA_Pub_x_bytes+SPKA_Pub_y_bytes

    print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them \n result will be like: {} \n ".format(SPKA_PUB_x_y_bytes))

    SPKA_h, SPKA_s = sign(SPKA_PUB_x_y_bytes, sA, n, P)
    
    print("Signature of SPK is: \n h = {} \n s = {} \n".format(SPKA_h,SPKA_s))

    print("if server verifies the signature it will send its SPK and corresponding signature. If this is the case SPKReg() function will return those")

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    # Registration of SPK

    print("\n Sending SPK and the signatures to the server via SPKReg() function in json format...")
    try:
        SPKS_Pub_x, SPKS_Pub_y, SPKS_h, SPKS_s = SPKReg(SPKA_h, SPKA_s, SPKA_Pub.x, SPKA_Pub.y)
        SPKS_Pub = Point(SPKS_Pub_x,SPKS_Pub_y,curve)
        pass
    except:
        print("Exception occured!")
        return

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")
    
    print("Server's SPK Verification \n")

    print("Recreating the message(SPK) signed by the server \n")

    SPKS_Pub_x_bytes = SPKS_Pub.x.to_bytes((SPKS_Pub.x.bit_length()+7)//8, 'big')
    SPKS_Pub_y_bytes = SPKS_Pub.y.to_bytes((SPKS_Pub.y.bit_length()+7)//8, 'big')
    SPKS_PUB_x_y_bytes = SPKS_Pub_x_bytes+SPKS_Pub_y_bytes

    print("Verifying the server's SPK...")
    print("If server's SPK is verified we can move to the OTK generation step")

    spk_verification = signature_verification(SPKS_PUB_x_y_bytes, SPKS_h, SPKS_s, n, IKey_Ser, P)

    print("Is SPK verified?:  {}".format(spk_verification))

    if(spk_verification == False):
        print("Could not verified!")
        ResetSPK(h,s)
        return
    else:
        pass

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    # kHMAC Generation

    print("Creating HMAC key (Diffie Hellman)")

    T = SPKA_Pri*SPKS_Pub
    T_x_bytes = T.x.to_bytes((T.x.bit_length()+7)//8, 'big')
    T_y_bytes = T.y.to_bytes((T.y.bit_length()+7)//8, 'big')
    U = T_x_bytes + T_y_bytes + b'NoNeedToRideAndHide'
    KHMAC = SHA3_256.new(U).digest()

    print("T is {}".format(T))
    print("U is {}".format(U))
    print("HMAC key is created {}".format(KHMAC))

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    # OTK Registration

    print("Creating OTKs starting from index 0...")
    OTK_NUM = 11

    for i in range(OTK_NUM):
        OTKA_Pri, OTKA_Pub = generate_key(n,P)
        print("********")
        print("{}th key generated. Private part= {}".format(i,OTKA_Pri))
        print("Public Public (x coordinate) = {}".format(OTKA_Pub.x))
        print("Public Public (y coordinate) = {} \n".format(OTKA_Pub.y))

        print("x and y coordinates of the OTK converted to bytes and concatanated")
        OTKA_i_Pub_x_bytes = OTKA_Pub.x.to_bytes((OTKA_Pub.x.bit_length()+7)//8, 'big')
        OTKA_i_Pub_y_bytes = OTKA_Pub.y.to_bytes((OTKA_Pub.y.bit_length()+7)//8, 'big')
        OTKA_i_Pub_x_y_bytes = OTKA_i_Pub_x_bytes + OTKA_i_Pub_y_bytes
        
        print("message {}".format(OTKA_i_Pub_x_y_bytes))

        hmaci = HMAC.new(key=KHMAC, msg=OTKA_i_Pub_x_y_bytes, digestmod=SHA256).hexdigest()

        print("hmac is calculated and converted with 'hexdigest()': {} \n".format(hmaci))

        OTKReg(i, OTKA_Pub.x, OTKA_Pub.y, hmaci)

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    # Resetting 
    print("Trying to delete OTKs but sending wrong signatures...")
    ResetOTK(h*2,s)

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")

    # Resetting 
    print("Trying to delete OTKs...")
    ResetOTK(h,s)

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")
    
    print("Trying to delete SPK...")
    ResetSPK(h,s)

    print("------------------------------------------------------------------------------------------------------------------------------------------------------------------- \n")
    
    print("Trying to delete Identity Key...")
    try:
         # Authentication
        rcode = int(input("Enter reset code which is sent to you: "))
        ResetIK(rcode)
    except Exception as e:
        print(e)
        return

main()