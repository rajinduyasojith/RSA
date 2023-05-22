import ED_byteSeq
import hashlib


def createDigitalCertificate(NameOfCA,PRofCA, EntityName, EntityPU):
    certPlaintext = "Name=" + EntityName + ";PU=" + str(EntityPU) + ";Signer=" + NameOfCA
    hashFunction = hashlib.sha256()
    hashFunction.update(bytes(certPlaintext,"ascii"))
    digest = hashFunction.digest()
    signature = ED_byteSeq.rsaEncryptBytes2Bytes(PRofCA,digest)
    return (certPlaintext,signature)

# Root CA self-signs a digital certificate for himself.
PR_Root_CA = (13,77)
PU_Root_CA = (37,77)
Root_CA_selfsignedCertificate = createDigitalCertificate("RootCA", PR_Root_CA, "RootCA", PU_Root_CA)
print(Root_CA_selfsignedCertificate)

def authenticDigitalCertificate(PUofCA,digitalCert):
    certPlaintext,signature = digitalCert
    hashFunction = hashlib.sha256()
    hashFunction.update(bytes(certPlaintext,"ascii"))
    recomputedDigest = hashFunction.digest()
    decryptedDigest = ED_byteSeq.rsaDecryptBytes2Bytes(PUofCA,signature)
    if recomputedDigest == decryptedDigest:
        return True
    else: return False
    
def retrievePUFromDigitalCertificate(PUofCA,digitalCert):
    if authenticDigitalCertificate(PUofCA,digitalCert):
        certPlaintext,signature = digitalCert
        return certPlaintext.split(";")[1].split("=")[1]
    else: return None
    
print(retrievePUFromDigitalCertificate(PU_Root_CA,Root_CA_selfsignedCertificate))
      

# Root CA signs a digital certificate for a sub-ordinate CA.
PR_Sub_CA = (303, 667)
PU_Sub_CA = (431,667)
certificateOfSubCA = createDigitalCertificate("RootCA",PR_Root_CA, "Sub-CA", PU_Sub_CA)

print(certificateOfSubCA)
print(retrievePUFromDigitalCertificate(PU_Root_CA,certificateOfSubCA))







