import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256 
from Crypto.Random import get_random_bytes
import imexceptions
from hmac import compare_digest


class EncryptedBlob:

    # the constructor
    def __init__(self, plaintext=None, confkey=None, authkey=None): 
        self.plaintext = plaintext
        self.ivBase64 = None
        self.ciphertextBase64 = None
        self.macBase64 = None

        if plaintext is not None:
            self.ivBase64, self.ciphertextBase64, self.macBase64 = self.encryptThenMAC(confkey, authkey, plaintext)



    # encrypts the plaintext and adds a SHA256-based HMAC
    # using an encrypt-then-MAC solution
    def encryptThenMAC(self,confkey,authkey,plaintext):
        # pad the plaintext to make AES happy
        plaintextPadded = pad(plaintext.encode('utf-8'), AES.block_size)
        
        iv = get_random_bytes(16)

        cipher = AES.new(confkey, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(plaintextPadded)
                        
        mac = HMAC.new(authkey, digestmod=SHA256)
        mac.update(iv + ciphertext)
        macDigest = mac.digest()

        # DON'T CHANGE THE BELOW.
        # What we're doing here is converting the iv, ciphertext,
        # and mac (which are all in bytes) to base64 encoding, so that it 
        # can be part of the JSON EncryptedIM object
        ivBase64 = base64.b64encode(iv).decode("utf-8") 
        ciphertextBase64 = base64.b64encode(ciphertext).decode("utf-8") 
        macBase64 = base64.b64encode(macDigest).decode("utf-8") 
       
        
        return ivBase64, ciphertextBase64, macBase64


    def decryptAndVerify(self,confkey,authkey,ivBase64,ciphertextBase64,macBase64):
        iv = base64.b64decode(ivBase64)
        ciphertext = base64.b64decode(ciphertextBase64)
        mac = base64.b64decode(macBase64)
    
        try:
            
            cipher = AES.new(confkey, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        except imexceptions.FailedDecryptionError:
            raise imexceptions.FailedDecryptionError("Failed to decrypt the ciphertext.")
         
        verifyMac = HMAC.new(authkey, digestmod=SHA256)
        verifyMac.update(iv + ciphertext)
        computed_mac = verifyMac.digest() 
      
        if not compare_digest(computed_mac, mac):
            raise imexceptions.FailedAuthenticationError("MAC verification failed")
        
        return plaintext.decode('utf-8')
