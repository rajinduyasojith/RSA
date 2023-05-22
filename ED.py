# {e, n} = (77,143)
# e = 77; n = 143
# (d, n ) = (53,143); d = 53, n = 143

# 0 <= M < n

# M = 50   ===> C  = M**77%143  = 50**77 %143  = 85

# C**53%143 = 85**53%143 





# test: rsaEncrypt((77,143),88)
def rsaEncrypt(key, M):
       (e,n) = key
       # plainNum in [0,n-1], 
       C = M**e % n
       return C


def rsaDecrypt(key, C):
       (d,n) = key
       M = C**d % n
       return M     
       

# one function for both encryption and descryption

def rsaED(key,Input):
       (ed,n)=key
       Out = Input**ed % n
       return Out

# Test:
 
PR = (77,143)
PU = (53,143)


M = 90
print("M=", M)
C = rsaEncrypt(PR,M)
print("Encryption result: C=", rsaEncrypt(PR,M))
Mdash = rsaDecrypt(PU, C)

print("Decrypt C got:", Mdash)


