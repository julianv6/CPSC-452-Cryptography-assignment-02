#include "AES.h"

/**
 * Sets the key to use
 * @param key - the first byte of this represents whether
 * to encrypt or to decrypt. 0 means encrypt and any other
 * value to decrypt.  Then come the bytes of the 128-bit key
 * (should be 16 of them).
 * @return - True if the key is valid and False otherwise
 */
bool AES::setKey(const unsigned char* keyArray)
{	
	if(strlen((char*)keyArray) !=33 ){
		fprintf(stderr, "Invalid key length!\n");
		return false;
	}
	//if the first byte is 0, then use AES_set_encrypt_key(...).
	if(keyArray[0]=='0'){
		/* Set the encryption key */
		if(AES_set_encrypt_key(keyArray+1, 128, &key)!=0){
			fprintf(stderr, "AES_set_encrypt_key() failed!\n");
			return false; 
		}
	}
	// Otherwise, use AES_set_decrypt_key(...).  
	else{
		/* Set the decryption key */
		if(AES_set_decrypt_key(keyArray+1, 128, &key) != 0){
			fprintf(stderr, "AES_set_decrypt_key() failed!\n");
			return false;
		}
	}	

	fprintf(stderr, "%s\n", "Key Set.");
	return true;
	
}

/**	
 * Encrypts a plaintext string
 * @param plaintext - the plaintext string
 * @return - the encrypted ciphertext string
 */
unsigned char* AES::encrypt(const unsigned char* plainText)
{
	
	//TODO: 1. Dynamically allocate a block to store the ciphertext.
	unsigned char* enc_out =  new unsigned char[17];
	memset(enc_out, 0, 17);
	//	2. Use AES_ecb_encrypt(...) to encrypt the text (please see the URL in setKey(...)
	//	and the aes.cpp example provided.
	/* Encrypt! */
	AES_ecb_encrypt(plainText, enc_out, &key, AES_ENCRYPT);
	// 	3. Return the pointer to the ciphertext		
	return enc_out;	
}

/**
 * Decrypts a string of ciphertext
 * @param cipherText - the ciphertext
 * @return - the plaintext
 */
unsigned char* AES::decrypt(const unsigned char* cipherText)
{
	
	//TODO: 1. Dynamically allocate a block to store the plaintext.
	unsigned char* dec_out =  new unsigned char[17];
	memset(dec_out, 0, 17);
	//	2. Use AES_ecb_encrypt(...) to decrypt the text (please see the URL in setKey(...)
	//	and the aes.cpp example provided.
	/* Decrypt! */
	AES_ecb_encrypt(cipherText, dec_out, &key, AES_DECRYPT);
	// 	3. Return the pointer to the plaintext
		
	return dec_out;
}



