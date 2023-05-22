# RSA encryption using key (e, n), e.g (303, 667). Note that the decryptiont key is (d,n) = (431, 667)
# m is a plain number such that 0 <= m < n
# test: encryptOneNumber(303, 667, 8) returns 565
def encryptOneNumber(e, n, m):
    return m**e%n
    # return the encryption of m



# encrypt a list of plain numbers
# test: encryptNumSeq(303, 667, [8, 99, 76]) returns [565, 249, 640]
def encryptNumSeq(e, n, ListOfm):
    r = []
    for m in ListOfm:
        c = encryptOneNumber(e, n, m)
        r.append(c)
    return r


# split a sequence of digits into a list of numbers, each of which is smaller than n
# test: splitDigitSeq(667, "089976") returns [8, 99, 76]
def splitDigitSeq(n, DigitSeq):
    size =len(str(n))-1
    if len(DigitSeq)<=size:
        return [int(DigitSeq)]
    else:
        return [int(DigitSeq[0:size])] + splitDigitSeq(n, DigitSeq[size:])



# encrypt a sequence of digits
# test: encryptDigitSeq(303, 667, "089976") returns '565249640'
def encryptDigitSeq(e, n, DigitSeq):
    ListOfm = splitDigitSeq(n, DigitSeq)
    ListOfc = encryptNumSeq(e, n, ListOfm)
    r = ""
    for c in ListOfc:
        c1 = str(c)
        if len(c1) < len(str(n)):
            c1 = "0"*(len(str(n)) - len(c1))   + c1
        
        r = r + c1
    return r       
    


# RSA descryption using key (d,n)
# c is a ciphered number such that 0 <=c < n
def decrypt(d, n, c):
    return c**d%n
    # return the decryption of c
   


    
# Example: splitCipherText(667, '565249640') ==> [565, 249, 640]
def splitCipherText(n, ciphertext):
    s = len(str(n))
    if len(ciphertext) <= s:
        L = [int(ciphertext)]
    else:
        L = [int(ciphertext[0:s])] + splitCipherText(n, ciphertext[s:])
    return L
    

#decryptDigitSeq(431, 667, '565249640') ==> '089976'

def decryptDigitSeq(d, n, ciphertext):
    ListOfC = splitCipherText(n, ciphertext)
    r = ""
    for c in ListOfC:
        m = c**d%n
        if len(str(m)) < len(str(n)) -  1:

            r = r +  "0"* (len(str(n)) -  1 - len(str(m))) + str(m)
        else:
            r = r + str(m)
    return r
    


############### now let's switch our attention to textual data

# test: string2BitSeq('siit') returns '01110011011010010110100101110100'
def string2BitSeq(a):
    l,m=[],[]
    for i in a:
        l.append(ord(i))
    for i in l:
        bitsOfi = bin(i).replace("b","")
        bitsOfi = "0" * (8-len(bitsOfi))+ bitsOfi
        m.append(bitsOfi)

    r = ""
    
    for c in m:
        r = r + c

    return r

def encryptString(e, n, plaintext):
    digitSeq  = string2BitSeq(plaintext)
    return encryptDigitSeq(e, n, digitSeq)


def decryptString(d,n,cipheredtext):
    bitSeq = decryptDigitSeq(d, n, cipheredtext)
    numOfBlocks = int(len(bitSeq)/8)
    r = ""
    for i in range(numOfBlocks): # i =0,1,...,numOfBlocks-1
        block_i = bitSeq[8*i: 8*i + 8]
        c = chr(int(block_i,2))
        r = r + c
    return r


plaintext = input("plaintext:")
cipheredtext = encryptString(303, 667, plaintext)
descryptedPlaintext = decryptString(431,667,cipheredtext)
print("The cipheredtext is:", cipheredtext)
print("encrypt, then descrypt => ",descryptedPlaintext)
        



    

    
