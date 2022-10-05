#ifndef __cstore_h__
#define __cstore_h__



///////////////////
// Structures
///////////////////

//Header for each stored file
typedef struct {

	char filename[256];
	size_t filesize;
	BYTE data[AES_BLOCK_SIZE];
} HEADER;

//Label for archive
typedef struct {

	char filetype[8];
	BYTE HMAC[SHA256_BLOCK_SIZE];
} LABEL;



///////////////////
// Supplementary Methods
///////////////////

//Returns number of bytes in file
size_t fileSize(const char *filename); // pointer to name of file

//Returns 1 if file is directory
int file_isDir(const char *file); // ponter to name of file

//Returns 1 if file is archive else 0
int isARCHIVE(const char *filename); //pointer to name of possible archive

//Returns 1 if integrity else 0
int integrity_check(const BYTE *key, // pointer to key
					const char *filename); // pointer to name of archive

//Sets HMAC
void integrity_set(const BYTE *key, // pointer to key
					const char *filename, // pointer to name of archive
					int new); // 1 if new archive or 0

//Check if file exists in archive
int file_exists(const char *filename, // pointer to name of archive
				const char *file); //pointer to name of file to look for in archive

//XOR function 
void XOR(BYTE *dest, //
		const BYTE *a, 
		const BYTE *b, 
		size_t length);

//Calculate HMAC
void calculate_HMAC(BYTE *buf, // pointer to destination to write HMAC
					const BYTE *key, // pointer to key
					const char *filename, // pointer to name of archive
					int new); // 1 if new archive or 0

//Return key from password
void getKey(BYTE *key, // pointer to destination to write key
			const char *password); // pointer to password



///////////////////
// Listing
///////////////////

//Opens <filename> and lists items if archive
void cstore_list(const char *filename); //pointer to name of archive



///////////////////
// Adding
///////////////////

//Encryption of datalength using AES
void encrypt_dataLength(BYTE *data, // pointer to write encrypted length
						const BYTE *key, // pointer to key
						const size_t data_length); // original data length

//create archive with filename
void create_archive(const BYTE *key, // pointer to key
					const char *filename); // pointer to name of archive

//Encryption using AES CBC
BYTE *cbc_encrypt(BYTE *cyphertext, // pointer to write cypher text
				const BYTE *plaintext, // pointer to plain text
				HEADER h, // Header of file to encrypt
				const BYTE *key); // pointer to key

//Add file to archive
void cstore_add(const BYTE *key, // pointer to key
				const char *archive, // pointer to name of archive
				const char *file); // pointer to name of file to add

//Opens <filename> and adds files
void cstore_add_files(const BYTE *key, // pointer to key
					const char *filename, // pointer to name of archive
					char **files); // pointer to array of file names to add



///////////////////
// Extracting
///////////////////

//Decryption of datalength using AES
size_t decrypt_dataLength(const BYTE *data, // pointer to encrypted data length
						const BYTE *key); // pointer to key

//Decryption using AES CBC
BYTE *cbc_decrypt(BYTE *plaintext, // pointer to destination to write plaintext
				const BYTE *cyphertext, // pointer to cyphertext
				HEADER h, // Header of file to decrypt
				const BYTE *key); // pointer to key

//Extract file from archive
void cstore_extract(const BYTE *key, // pointer to key
				const char *filename, // pointer to name of archive
				const char *file); // pointer to name of file to extract

//Opens <filename> and extracts files
void cstore_extract_files(const BYTE *key, // pointer to key
						const char *filename, // pointer to name of archive
						char **files); // pointer to array of file names to add



///////////////////
// Deleting
///////////////////

//Takes in list of files and returns 1 if h.filename is in list
int is_delete(HEADER h, // Header of possible file to delete
			char **files, // pointer to array of file names to delete
			const int queue[], // array showing files yet to delete
			const int length); // length of queue

//Opens <filename> and deletes files
void cstore_delete_files(const BYTE *key, // pointer to key
					const char *filename, // pointer to name of archive
					char **files); // pointer to array of file names to delete



#endif