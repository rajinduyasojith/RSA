from RSA_final import *
# Generate RSA key pair
private_key_pem, public_key_pem = generate_rsa_key_pair()

# Sample message
email_content = "Hello, this is a secure email."

# Sign the message
signature = sign_message(email_content.encode(), private_key_pem)

# Verify the signature
is_signature_valid = verify_signature(email_content.encode(), signature, public_key_pem)
print(f"Is signature valid? {is_signature_valid}")

# Encrypt the message with RSA public key
encrypted_content = rsa_encrypt(email_content.encode(), public_key_pem)

# Decrypt the encrypted content with RSA private key
decrypted_content = rsa_decrypt(encrypted_content, private_key_pem)

# Encrypt the decrypted content with 3DES
des_key = os.urandom(24)
encrypted_email = encrypt_with_3des(des_key, decrypted_content)
print(encrypted_email)

# Decrypt the encrypted email with 3DES
decrypted_email = decrypt_with_3des(des_key, encrypted_email)
print(decrypted_email.decode()) 