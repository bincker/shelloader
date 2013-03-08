/* shelloader.c - Linux 64-Bit mmap based shell code loader
 *-------------------------------------------------------------------------
 * pass it your object file and it will display and execute the shellcode
 * date 3/8/2013
 * author Travis "rjkall"
 *-------------------------------------------------------------------------
 * http://www.blackhatlibrary.net
 *
 * UPDATES:
 * - Added more verbose output for user
 * - Added null byte warning
 *------------------------------------------------------------------------
 *  (C) Copyright 2013 Travis "rjkall"
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <assert.h>

/* 
 * This function parses the object file, displays the shellcode and then sends it to execute
 * it is sort of messy, I may clean it up later.
*/
int parse(char *obj_file) {
	/* ELF variables */
	FILE *obj;
	Elf64_Ehdr ehdr;
	Elf64_Shdr *shdr;

	/* Misc variables for data manipulation */
	char sname[6];
	int sections = 0;
	int addrlen = 0;
	int addr = 0;
	int i = 0;
	int nullcntr = 0;
	
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
			printf("[*] EI_MAG0 = 0x7f, continuing.\n");
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
				printf("[*] Found .text section at address 0x%08x with length of %d bytes.\n",addr,addrlen);
				printf("[*] Dumping shellcode.\n");
		
				/*
				 * sh_offset is the offset of the section data from the beginning
                                 * of the file so we seek to the beginning THEN the offset
				*/
				fseek(obj,0L,SEEK_SET);
				fseek(obj,shdr[sections].sh_offset,SEEK_SET);
				unsigned char obj_data[addrlen+1];
	
				fgets(obj_data,addrlen+1,obj);
				while(i<=addrlen-1) {
					if(strlen(obj_data) <= addrlen-1) {
      						if(obj_data[i] == 0) {
               						nullcntr++;
          					}
     					}

          				printf("\\x%02x",obj_data[i++]);
				}
				
				close(obj);	
				
				/*
				 * If null bytes were detected warn user
				*/
				if(nullcntr > 0) {
					printf("\n[*] WARNING: Detected %d null bytes!",nullcntr);
				}

				/*
				 * Finally execute the byte code
				*/
				executecode(obj_data,addrlen);
				
			}
		}
	}

	return 0;
}

/*
 * copy shellcode to memory we have mapped and execute it
 * -has been known to be a bit buggy on some systems
*/
int executecode(unsigned char *exshellcode, int shellen) {
	unsigned char *shellcode;

	printf("\n[*] Mapping and copying %d bytes of shellcode to memory.\n",shellen);	
	shellcode = (unsigned char *)mmap(0,shellen-1,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
	memcpy(shellcode, exshellcode,shellen);
	
	printf("[*] Executing shellcode at address %p.\n",shellcode);
	(*(void(*)()) shellcode)();

	return 0;
}

/*
 * Program begins execution at this point, at the moment I don't have any further
 * plans of adding features to it
*/
int main(int argc, char *argv[]) {

	printf("Linux 64-Bit mmap based shellcode loader by Travis \"rjkall\".\n");
	
	/* Just check whether we have a file argument or not*/
	if(argc > 1) {
		parse(argv[1]);
	} else {
		printf("usage: %s <file>\n",argv[0]);
		printf("file should be an ELF object file.\n");
	}

	return 0;
}					
