#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>

#include <aes.h>
#include <sha256.h>

#include "cstore.h"

///////////////////
// Supplementary Methods
///////////////////

size_t fileSize(const char *filename){

	struct stat finfo;
	stat(filename, &finfo);
	return finfo.st_size;
}

int file_isDir(const char *file){

	struct stat finfo;
	if (stat(file, &finfo) == 0){
		return S_ISDIR(finfo.st_mode);
	}

	return 0;
}

int isARCHIVE(const char *filename){

	//Make sure file isn't directory
	if(file_isDir(filename)){
		return 0;
	}

	LABEL label;
	FILE *file;

	//Make sure file opens and is larger than LABEL
	if((file  = fopen(filename, "rb")) && fileSize(filename) >= sizeof(LABEL)){

		fread(&label, sizeof(LABEL), 1, file);

		//Make sure file label says "archive"
		if(strcmp(label.filetype, "archive") == 0){
			fclose(file);
			return 1;
		}

		fclose(file);
	}

	return 0;
}

int integrity_check(const BYTE *key, const char *filename){

	// Calculate HMAC
	BYTE buffer[SHA256_BLOCK_SIZE];
	calculate_HMAC(buffer, key, filename, 0);

	// Read HMAC from file
	LABEL label;
	FILE *archive = fopen(filename, "rb");
	fread(&label, sizeof(LABEL), 1, archive);
	fclose(archive);

	// Compare and return 1 if same
	if(memcmp(buffer, label.HMAC, SHA256_BLOCK_SIZE) == 0){
		return 1;
	}

	return 0;
}

void integrity_set(const BYTE *key, const char *filename, int new){

	// Create label with correct filetype
	LABEL label;
	sprintf(label.filetype, "archive");

	// Calculate HMAC
	calculate_HMAC(label.HMAC, key, filename, new);

	// Write label into file
	FILE *archive = fopen(filename, "r+b");
	fseek(archive, 0L,SEEK_SET);
	fwrite(&label, sizeof(LABEL), 1, archive);
	fclose(archive);
}


int file_exists(const char *filename, const char *file){


	// Open archive and skip LABEL
	FILE *archive = fopen(filename, "rb");
	fseek(archive, sizeof(LABEL), SEEK_SET);

	// Parse through headers
	HEADER h;
	while(fread(&h, sizeof(HEADER), 1, archive)){
		
		// Return 1 if name matches file	
		if(strcmp(file, h.filename) == 0){
			fclose(archive);
			return 1;
		}

		fseek(archive, h.filesize, SEEK_CUR);
	}

	// Return 0 if you reach end of file
	fclose(archive);
	return 0;
}

void XOR(BYTE *dest, const BYTE *a, const BYTE *b, size_t length){

	// XOR each byte into dest
	for(int i = 0; i < length; i++){

		dest[i] = a[i] ^ b[i]; 
	}
}

void calculate_HMAC(BYTE *buf, const BYTE *key, const char *filename, int new){

	// Create buffers
	BYTE innerbuf[SHA256_BLOCK_SIZE];
	BYTE *message;
	SHA256_CTX ctx;

	// Get length of archive
	size_t filesize = fileSize(filename);

	// Inner and outer pads for HMAC
	BYTE innerpad[SHA256_BLOCK_SIZE] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
	BYTE outerpad[SHA256_BLOCK_SIZE] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};

	// Create new key by appending "i" to key
	BYTE newkey[SHA256_BLOCK_SIZE + 1];
	memcpy(newkey, key, SHA256_BLOCK_SIZE);
	newkey[SHA256_BLOCK_SIZE] = (BYTE)'i';

	// SHA256 to create integrity key
	BYTE integrity_key[SHA256_BLOCK_SIZE];
	sha256_init(&ctx);
	sha256_update(&ctx, newkey, SHA256_BLOCK_SIZE + 1);
	sha256_final(&ctx, integrity_key);

	// XOR integrity_key with innerpad
	XOR(innerpad, innerpad, integrity_key, SHA256_BLOCK_SIZE);

	// SHA256 with entire archive 
	message = malloc(SHA256_BLOCK_SIZE + filesize - sizeof(LABEL));
	memcpy(message, innerpad, SHA256_BLOCK_SIZE);
	FILE *archive = fopen(filename, "rb");
	fseek(archive, sizeof(LABEL), SEEK_SET);
	fread(message + SHA256_BLOCK_SIZE, filesize - sizeof(LABEL), 1, archive);
	fclose(archive);

	sha256_init(&ctx);
	sha256_update(&ctx, message, SHA256_BLOCK_SIZE + filesize - sizeof(LABEL));
	sha256_final(&ctx, innerbuf);

	free(message);


	// XOR integrity key with outerpad
	XOR(outerpad, outerpad, integrity_key, SHA256_BLOCK_SIZE);
	
	// SHA256 with result from inner
	message = malloc(2 * SHA256_BLOCK_SIZE);
	memcpy(message, outerpad, SHA256_BLOCK_SIZE);
	memcpy(message + SHA256_BLOCK_SIZE, innerbuf, SHA256_BLOCK_SIZE);

	sha256_init(&ctx);
	sha256_update(&ctx, message, 2 * SHA256_BLOCK_SIZE);
	sha256_final(&ctx, buf);

	free(message);
}

void getKey(BYTE *key, const char *password){

	SHA256_CTX ctx;

	// Iterate SHA256 on password 10000 times
	sha256_init(&ctx);
	for (int i = 0; i < 100000; i++)
	   sha256_update(&ctx, (const BYTE *) password, strlen(password));
	sha256_final(&ctx, key);
}



///////////////////
// Listing
///////////////////

void cstore_list(const char *filename){

	// Make sure file is archive
	if(isARCHIVE(filename)){

		printf("\nListing from <%s>\n\n", filename);

		// Open and skip LABEL
		FILE *archive = fopen(filename, "rb");
		fseek(archive, sizeof(LABEL), SEEK_SET);

		// Parse through headers
		HEADER h;
		while(fread(&h, sizeof(HEADER), 1, archive)){
			
			// Print filenames from headers
			printf("\t%s\n", h.filename);
			fseek(archive, h.filesize, SEEK_CUR);
		}

		printf("\n");
		fclose(archive);
	}

	else{

		printf("\nNo archive <%s>\n\n", filename);
	}
}



///////////////////
// Adding
///////////////////

void encrypt_dataLength(BYTE *data, const BYTE *key, const size_t data_length){

	SHA256_CTX ctx;

	// Create new key by appending 'l'
	BYTE newkey[SHA256_BLOCK_SIZE + 1];
	memcpy(newkey, key, SHA256_BLOCK_SIZE);
	newkey[SHA256_BLOCK_SIZE] = (BYTE)'l';

	// SHA256 to create dataLength_key 
	BYTE dataLength_key[SHA256_BLOCK_SIZE];
	sha256_init(&ctx);
	sha256_update(&ctx, newkey, SHA256_BLOCK_SIZE + 1);
	sha256_final(&ctx, dataLength_key);

	// Pad dataLength with random bytes
	BYTE dataLen[AES_BLOCK_SIZE];
	memcpy(dataLen, &data_length, sizeof(size_t));
	FILE *random = fopen("/dev/urandom", "rb");
	fread(dataLen + sizeof(size_t), AES_BLOCK_SIZE - sizeof(size_t), 1, random);
	fclose(random);

	// encrypt padded dataLength
	WORD key_schedule[60];
	aes_key_setup(dataLength_key, key_schedule, 256);
	aes_encrypt(dataLen, data, key_schedule, 256);
}

void create_archive(const BYTE *key, const char *filename){

	// Create new file with filename
	FILE *archive = fopen(filename, "wb");

	// Create and write LABEL with 0 HMAC value
	LABEL label;
	sprintf(label.filetype, "archive");
	memset(label.HMAC, 0,  SHA256_BLOCK_SIZE);
	fwrite(&label, sizeof(LABEL), 1, archive);
	fclose(archive);

	// Set integrity HMAC
	integrity_set(key, filename, 1);
}

BYTE *cbc_encrypt(BYTE *cyphertext, const BYTE *plaintext, HEADER h, const BYTE *key){

	// Decrypt dataLength of plaintext
	size_t data_length = decrypt_dataLength(h.data, key);
    size_t padding = h.filesize - data_length;

	// Copy plaintext to buffer
	BYTE *plain = malloc(h.filesize);
	if(plain == NULL){
        perror("malloc returned NULL");
        exit(1);
    }
    memcpy(plain, plaintext, data_length);

    // Pad with random bytes
	FILE *random = fopen("/dev/urandom", "rb");
	fread(plain + data_length, padding, 1, random);

	// Create buffers
	BYTE input[AES_BLOCK_SIZE];
	BYTE output[AES_BLOCK_SIZE];
	BYTE buf[AES_BLOCK_SIZE];

	// Create iv and copy to cyphertext
	fread(buf, AES_BLOCK_SIZE, 1, random);
	fclose(random);
	memcpy(cyphertext, buf, AES_BLOCK_SIZE);

	// CBC encrypt through plaintext
	int length = h.filesize / AES_BLOCK_SIZE;

	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, 256);

	for(int i = 0; i < length - 1; i++){

		memcpy(input, plain + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		XOR(input, buf, input, AES_BLOCK_SIZE);
		aes_encrypt(input, output, key_schedule, 256);
		memcpy(cyphertext + i * AES_BLOCK_SIZE + AES_BLOCK_SIZE, output, AES_BLOCK_SIZE);
		memcpy(buf, output, AES_BLOCK_SIZE);
	}

	free(plain);

	return cyphertext;
}

void cstore_add(const BYTE *key, const char *filename, const char *file){

	// Make sure file doesn't exist in archive
	if(file_exists(filename, file)){

		printf("\t%s already in archive\n", file);
		return;
	}

	//Make sure file isn't directory
		if(file_isDir(file)){
			printf("\t%s is a directory\n", file);
			return;
		}

	// Open archive at end
	FILE *archive = fopen(filename, "ab");

	// Make sure file exists
	FILE *fp;
	if((fp = fopen(file, "rb"))){

		//Create header
		HEADER h;
		memset(&h, 0, sizeof(HEADER));
		sprintf(h.filename, "%s", file);

		// Encrypt file length
		size_t data_length = fileSize(h.filename);
		encrypt_dataLength(h.data, key, data_length);
		size_t padding = AES_BLOCK_SIZE - (data_length % AES_BLOCK_SIZE);
		h.filesize = data_length + padding + AES_BLOCK_SIZE;

		// Make sure padded length is multiple of AES_BLOCK_SIZE
		if(h.filesize % AES_BLOCK_SIZE != 0){

			printf("Uh oh\n");

			fclose(fp);
	        fclose(archive);
	        return;

		}

		// Copy plaintext to buffer
		BYTE *plaintext = malloc(data_length);
		if(plaintext == NULL){
            perror("malloc returned NULL");
            exit(1);
        }

        memset(plaintext, 0, data_length);
        fread(plaintext, data_length, 1, fp);
        fclose(fp);

        // Encrypt plaintext to cyphertext
        BYTE *cyphertext = malloc(h.filesize);
        if(cyphertext == NULL){
            perror("malloc returned NULL");
            exit(1);
        }

        memset(cyphertext, 0, h.filesize);
        cyphertext = cbc_encrypt(cyphertext, plaintext, h, key);

        // Write header and cyphertext to archive
        fwrite(&h, sizeof(HEADER), 1, archive);
        fwrite(cyphertext, h.filesize, 1, archive);
        fclose(archive);

        free(plaintext);
        free(cyphertext);

        printf("\t%s successfully archived\n", file);

        remove(file);
        return;

	} 

	else{

		printf("\t%s does not exist\n", file);
		fclose(archive);
		return;
	}

}

void cstore_add_files(const BYTE *key, const char *filename, char **files){

	// Create archive if doesn't exist yet
	if(!isARCHIVE(filename)){

		create_archive(key, filename);
	}

	// Check archive integrity
	if(!integrity_check(key, filename)){
		printf("\n\tIntegrity Compromised\n\n");
		exit(1);
	}

	printf("\nAdding to <%s>\n\n", filename);

	// Add files
	int i = 0;
	while(files[i]){

		cstore_add(key, filename, files[i++]);
	}

	printf("\n");

	//Set integrity HMAC
	integrity_set(key, filename, 0);
}



///////////////////
// Extracting
///////////////////

size_t decrypt_dataLength(const BYTE *data, const BYTE *key){

	SHA256_CTX ctx;

	// Create new key by appending 'l'
	BYTE newkey[SHA256_BLOCK_SIZE + 1];
	memcpy(newkey, key, SHA256_BLOCK_SIZE);
	newkey[SHA256_BLOCK_SIZE] = (BYTE)'l';

	// SHA256 to create dataLength_key
	BYTE dataLength_key[SHA256_BLOCK_SIZE];
	sha256_init(&ctx);
	sha256_update(&ctx, newkey, SHA256_BLOCK_SIZE + 1);
	sha256_final(&ctx, dataLength_key);
	
	// Decrypt to data_length buf
	WORD key_schedule[60];
	aes_key_setup(dataLength_key, key_schedule, 256);
	BYTE data_length[AES_BLOCK_SIZE];
	aes_decrypt(data, data_length, key_schedule, 256);
	
	// Copy to len minus the padding
	size_t len;
	memcpy(&len, data_length, sizeof(size_t));
	return len;
}

BYTE *cbc_decrypt(BYTE *plaintext, const BYTE *cyphertext, HEADER h, const BYTE *key){


	BYTE *plain = malloc(h.filesize);
	if(plain == NULL){
        perror("malloc returned NULL");
        exit(1);
    }

    // Create buffers
	BYTE input[AES_BLOCK_SIZE];
	BYTE output[AES_BLOCK_SIZE];
	BYTE buf[AES_BLOCK_SIZE];

	// Copy iv from cyphertext
	memcpy(buf, cyphertext, AES_BLOCK_SIZE);

	// CBC decrypt through cyphertext
	int length = h.filesize / AES_BLOCK_SIZE;

	WORD key_schedule[60];
	aes_key_setup(key, key_schedule, 256);

	for(int i = 0; i < length - 1; i++){

		memcpy(input, cyphertext + i * AES_BLOCK_SIZE + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		aes_decrypt(input, output, key_schedule, 256);
		XOR(output, buf, output, AES_BLOCK_SIZE);
		memcpy(plain + i * AES_BLOCK_SIZE, output, AES_BLOCK_SIZE);
		memcpy(buf, input, AES_BLOCK_SIZE);
	}

	// Decrypt data_length
	size_t data_length = decrypt_dataLength(h.data, key);

	// Copy over minus padding
	memcpy(plaintext, plain, data_length);
	free(plain);

	return plaintext;
}

void cstore_extract(const BYTE *key, const char *filename, const char *file){

	// Make sure file exists in archive
	if(!file_exists(filename, file)){

		printf("\t%s not in archive\n", file);
		return;
	}

	// Open archive and skip LABEL
	FILE *archive = fopen(filename, "rb");
	fseek(archive, sizeof(LABEL), SEEK_SET);

	// Parse through headers
	HEADER h;
	while(fread(&h, sizeof(HEADER), 1, archive)){
		
		if(strcmp(h.filename, file) == 0){
			break;
		}
		
		fseek(archive, h.filesize, SEEK_CUR);
	}

	// Make sure filesize is multiple of AES_BLOCK_SIZE
	if(h.filesize % AES_BLOCK_SIZE != 0){

		printf("Uh oh\n");

        fclose(archive);
        return;

	}

	// Copy cyphertext to buffer
	BYTE *cyphertext = malloc(h.filesize);
	if(cyphertext == NULL){
        perror("malloc returned NULL");
        exit(1);
    }
    fread(cyphertext, h.filesize, 1, archive);

    // Decrypt datalength
    size_t data_length = decrypt_dataLength(h.data, key);

    // Decrypt cyphertext to plaintext
    BYTE *plaintext = malloc(data_length);
    if(plaintext == NULL){
        perror("malloc returned NULL");
        exit(1);
    }
    plaintext = cbc_decrypt(plaintext, cyphertext, h, key);

    // Copy plaintext to file
    FILE *fp = fopen(file, "wb");
    fwrite(plaintext, data_length, 1, fp);
    fclose(fp);

    free(cyphertext);
    free(plaintext);

    printf("\t%s successfully unarchived\n", file);

    fclose(archive);
    return;


}

void cstore_extract_files(const BYTE *key, const char *filename, char **files){

	// Check archive integrity
	if(!integrity_check(key, filename)){
		printf("\n\tIntegrity Compromised\n");
		exit(1);
	}

	printf("\nExtracting from <%s>\n\n", filename);

	// Extract files
	int i = 0;
	while(files[i]){

		cstore_extract(key, filename, files[i++]);
	}

	printf("\n");
}



///////////////////
// Deleting
///////////////////

int is_delete(HEADER h, char **files, const int queue[], const int length){

	// Go through queue and make sure index of file is yet to be deleted
	for (int i = 0; i < length; i++){

		if(queue[i] && strcmp(h.filename, files[i]) == 0){
			return i;
		}
	}

	return -1;
}

void cstore_delete_files(const BYTE *key, const char *filename, char **files){

	// Check archive integrity
	if(!integrity_check(key, filename)){
		printf("\n\tIntegrity Compromised\n");
		exit(1);
	}

	printf("\nDeleting from <%s>\n\n", filename);

	// Count number of files to delete
	int i = 0;
	while(*(files + i)){
		i++;
	}
	int length = i;

	// Create queue with each index of files 1
	int queue[length];
	for(i = 0; i < length; i++){
		queue[i] = 1;
	}

	// Open archive and allocate memory for temp
	FILE *archive = fopen(filename, "rb");
	BYTE *temp = malloc(fileSize(filename));

	// Copy LABEL into temp
	fread(temp, sizeof(LABEL), 1, archive);

	// Mark end of copy location
	size_t loc = sizeof(LABEL);

	// Parse through headers
	HEADER h;
	while(fread(&h, sizeof(HEADER), 1, archive)){

		// If files[i] is yet to be deleted
		if((i = is_delete(h, files, queue, length)) != -1){

			// Mark index has been deleted in queue
			queue[i] = 0;

			// Don't copy data
			fseek(archive, h.filesize, SEEK_CUR);

			printf("\t%s successfully deleted\n", files[i]);
			continue;
		}

		else{

			//Copy over to temp and increment loc
			memcpy(temp + loc, &h, sizeof(HEADER));
			loc += sizeof(HEADER);

			fread(temp + loc, h.filesize, 1, archive);
			loc += h.filesize;
		}
	}

	fclose(archive);

	// Go through queue for not yet deleted
	for(i = 0; i < length; i++){

		if(queue[i]){

			printf("\t%s not in archive\n", files[i]);
		}
	}

	printf("\n");

	// Recreate archive and copy over temp
	archive = fopen(filename, "wb");
	fwrite(temp, loc, 1, archive);
	fclose(archive);
	free(temp);

	// Set integrity HMAC
	integrity_set(key, filename, 0);
}



int main(int argc, char **argv){

	char *password;
	BYTE key[SHA256_BLOCK_SIZE];

	if(argc == 3 && strcmp(argv[1], "list") == 0){

		cstore_list(argv[2]);
		return 0;
	}

	else if(argc > 3){

		if(strcmp(argv[1], "add") == 0){

			if(strcmp(argv[2], "-p") == 0){

				if(argc >= 6){

					if(file_isDir(argv[4])){
						printf("\nCan't create archive with existing directory <%s>\n\n", argv[4]);
						return 0;
					}

					password = argv[3];
					getKey(key, password);
					cstore_add_files(key, argv[4], argv + 5);

					return 0;
				}
			}

			else if(argc >= 4){

				if(file_isDir(argv[2])){
					printf("\nCan't create archive with existing directory <%s>\n\n", argv[2]);
					return 0;
				}

				password = getpass("Enter password:");
				getKey(key, password);
				free(password);
				cstore_add_files(key, argv[2], argv + 3);
				return 0;
			}
		}

		if(strcmp(argv[1], "extract") == 0){

			if(strcmp(argv[2], "-p") == 0){

				if(argc >= 6){

					if(!isARCHIVE(argv[4])){

						printf("\nNo archive <%s>\n\n", argv[4]);
						return 0;
					}

					password = argv[3];
					getKey(key, password);
					cstore_extract_files(key, argv[4], argv + 5);

					return 0;
				}
			}

			else if(argc >= 4){

				if(!isARCHIVE(argv[2])){

					printf("\nNo archive <%s>\n\n", argv[2]);
					return 0;
				}

				password = getpass("Enter password:");
				getKey(key, password);
				free(password);
				cstore_extract_files(key, argv[2], argv + 3);
				return 0;
			}
		}

		if(strcmp(argv[1], "delete") == 0){

			if(strcmp(argv[2], "-p") == 0){

				if(argc >= 6){

					if(!isARCHIVE(argv[4])){

						printf("\nNo archive <%s>\n\n", argv[4]);
						return 0;
					}

					password = argv[3];
					getKey(key, password);
					cstore_delete_files(key, argv[4], argv + 5);
					
					return 0;
				}
			}

			else if(argc >= 4){

				if(!isARCHIVE(argv[2])){

					printf("\nNo archive <%s>\n\n", argv[2]);
					return 0;
				}
				
				password = getpass("Enter password:");
				getKey(key, password);
				free(password);
				cstore_delete_files(key, argv[2], argv + 3);
				return 0;
			}
		}	

	}
	
	printf("\n!! Wrong Usage !!\n\n");
	printf("Only the following commands are allowed:\n\n");
	printf("\tcstore list <archivename> \
		\n\tcstore add [-p key] <archivename> <files> \
		\n\tcstore extract [-p key] <archivename> <files> \
		\n\tcstore delete [-p key] <archivename> <files>\n\n");

	return 0;


}
