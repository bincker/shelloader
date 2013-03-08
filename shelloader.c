/* shelloader.c - Linux 64-Bit mmap based shell code loader
 * pass it your object file and it will display and execute the shellcode
 * date 3/8/2013
 * author Travis "rjkall"
 *
 * NOTE: Still buggy, work in progress.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>


/* 
 * This function parses the object file, displays and executes the shellcode
 * it is sort of messy, I may clean it up later.
*/
int parse(char *obj_file,int *f_size) {
	/* ELF variables */
	FILE *obj;
	Elf64_Ehdr ehdr;
	Elf64_Shdr *shdr;

	/* Misc variables for data manipulation */
	unsigned char *shellcode;
	int sections = 0;
	char sname[6];
	int i = 0;
	int addrlen = 0;
	int addr = 0;
	
	if((obj=fopen(obj_file,"r+b")) == NULL) {
		printf("[*] Unable to open %s! Quitting.\n",obj_file);
		return -1;
	} else {
		/*
		 * First step is to check that this is a valid ELF object file
		 * I only check EI_MAG0 not EI_MAG0-3, I figured it is good
                 * enough for this purpose.
		*/
		printf("[*] Examining %s...\n",obj_file);
		fread(&ehdr,sizeof(ehdr),1,obj);
		if(ehdr.e_ident[EI_MAG0] != 0x7f) {
			printf("[*] %s is not a valid ELF object file!\n",obj_file);
			return -1;
		} else {
			printf("[*] EI_MAG0 = 0x7f, continuing...\n");
		}
				
		shdr = (Elf64_Shdr *)malloc(sizeof(shdr));

		/*
		 * Complicated little process here.
                 * - first we loop through the sections finding .text
		 * - get size and address of .text section
		 * - seek to offest of the data and copy it to a buffer
		 * - display shellcode in C format
		 * - then execute shellcode
		*/
		fseek(obj,ehdr.e_shoff,SEEK_SET);
		fread(shdr, sizeof(*shdr), ehdr.e_shnum, obj);
		while(sections++ < ehdr.e_shnum) {		
			fseek(obj,shdr[ehdr.e_shstrndx].sh_offset+shdr[sections].sh_name,SEEK_SET);
			fgets(sname,6,obj);
			if((strncmp(sname,".text",5)) == 0) {

				/*
				 * This just makes it less messy but still to long of string
				*/
				addr = shdr[sections].sh_offset;
				addrlen = shdr[sections].sh_size;
				printf("[*] Found .text section at address 0x%08x with length of %d bytes\n",addr,addrlen);
				printf("[*] Dumping shellcode...\n");
		
				/*
				 * sh_offset is the offset of the section data from the beginning
                                 * of the file so we seek to the beginning THEN the offset
				*/
				fseek(obj,0L,SEEK_SET);
				fseek(obj,shdr[sections].sh_offset,SEEK_SET);
				unsigned char obj_data[addrlen+1];
	
				fgets(obj_data,addrlen+1,obj);
				while(i<=addrlen-1) {
					printf("\\x%02x",obj_data[i++]);
				}
				
				/*
				 * Map memory for our shellcode and execute it
				*/
			        shellcode = (unsigned char *)mmap(0,addrlen-1,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
				memcpy(shellcode, obj_data,addrlen);
				
				printf("\n[*] Executing shellcode...\n");
				(*(void(*)()) shellcode)();
				
				/* We should never reach here */
				return 0;
			}
		}

		fclose(obj);
	}

 return 0;
}

int main(int argc, char *argv[]) {
	int f_size;

	if(argc > 1) {
		parse(argv[1],&f_size);
	} else {
		printf("usage: %s <file>\n",argv[0]);
	}

	return 0;
}					
