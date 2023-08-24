from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
def generate_keys():
 private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
 )
 public = private.public_key()  #inbuild function
 return private,public

def sign(message,private):  # message is in string form
  message=bytes(str(message),'utf-8') #converting message to bytes.

  signature = private.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
  return signature

def verify(message,sig,public):
  message=bytes(str(message),'utf-8')
  try:
    public.verify(
    sig,
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    return True
  except InvalidSignature:
    return False
  except:
    print("error exectuing public key")
    return False
    
if __name__=='__main__':

    pr, pu = generate_keys()
    pr1,pu1 = generate_keys()
    print(pr)
    print(pu)

    message="Hi i am Blockchain Developer"
    sig=sign(message,pr)
    print(sig)
    correct=verify(message,sig,pu)
    if correct:
      print("Succesful")
    else:
      print("failed")

    
  
      
      
  
  
