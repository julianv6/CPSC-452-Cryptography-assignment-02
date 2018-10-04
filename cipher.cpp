#include "CipherInterface.h"
#include "DES.h"
#include "AES.h"
#include <string>
#include <fstream>

using namespace std;

#define ENC 1
#define DEC 0

//./cipher <CIPHER NAME> <KEY> <ENC/DEC> <INPUT FILE> <OUTPUT FILE>
int main(int argc, char** argv)
{
	if (argc != 6){
		fprintf(stderr, "INVALID ARGUMENT must look like:\n./cipher <CIPHER NAME> <KEY> <ENC/DEC> <INPUT FILE> <OUTPUT FILE>\n");
		return 0;
	}

	FILE* inputFile = fopen(argv[4], "r");
	if(!inputFile){
		perror("fopen");
		exit(-1);
	}
	

	FILE* outputFile = fopen(argv[5], "w");
	if(!outputFile){
		perror("fopen");
		exit(-1);
	}

	CipherInterface* cipher;	
	if(!strcmp(argv[1], "AES")){	
		 cipher = new AES();		
	}
	else if(!strcmp(argv[1], "DES")){
		cipher = new DES();
	}
	else{
		fprintf(stderr, "INVALID ARGUENT <CIPHER NAME>\n\tCIPHER NAME: The name of the cipher:\n\t\t– DES: indicates the DES cipher\n\t\t– AES: indicates the AES ciphe\n");
		return 0;
	}
	if(!cipher){
		fprintf(stderr, "ERROR [%s %s %d]: could not allocate memory\n",	
		__FILE__, __FUNCTION__, __LINE__);
		exit(-1);
	}

	unsigned char* block; 
	int blockSize;
	/*
	ENC/DEC: whether to encrypt or decrypt, respectively
	*/
	bool encrypt;
	if(!strcmp(argv[3], "ENC"))
		encrypt = true;
	else if(!strcmp(argv[3], "DEC"))
		encrypt = false;
	else{
		fprintf(stderr, "INVALID ARGUMENT <ENC/DEC>\n\twhether to encrypt or decrypt, respectively\n");

		return 0;
	}
	
	/* Set the encryption key */
	if(!strcmp(argv[1], "DES")){
		if(!cipher->setKey((unsigned char*)argv[2])){
			fprintf(stderr, "INVALID ARGUENT <KEY>\n\tthe encryption key to use (must be 16 characters representing a 64-bit hexadecimal number for DES and 128-bit number for AES\n");
			return 0;
		}
		block = new unsigned char[8];
		blockSize = 8;

	}
	//AES
	else{
		//add 0 or 1 to front of given key
		unsigned char* key = new unsigned char[33];
		memset(key, 0, 33);

		if(encrypt){
			key[0] = '0';
		}
		else{
			key[0] = '1';
		}

		for(int i =1; i<33; i++){
				key[i] = (char)argv[2][i-1];
		}

		if(!cipher->setKey((const unsigned char*)key)){
			fprintf(stderr, "Error Setting Key\n");
			return 0;
		}

		block = new unsigned char[16];
		blockSize = 16;
	}
	
	int numRead = 0;

	while(!feof(inputFile)){
		memset(block, '\0', blockSize);
		numRead = fread(block, 1, blockSize, inputFile);
		if(numRead==0){
			break;
		}

		if(encrypt){
			block = cipher->encrypt(block);
		}
		else{
			block = cipher->decrypt(block);
		}
		fwrite(block, sizeof(char), blockSize, outputFile);
	}

	fclose(inputFile);
	fclose(outputFile);
	return 0;
}
