/* shelloader.c - Linux 64-Bit mmap based shell code loader
 *-------------------------------------------------------------------------
 * pass it your object file and it will display and execute the shellcode
 * date 3/8/2013
 * author Travis "rjkall"
 * http://www.blackhatlibrary.net
 *
 * UPDATES:
 * - Variable fixes, usage,  check entire e_ident now
 * - Added line breaking for shellcode dump
 * - Added option to execute shellcode or just display shellcode
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

#define LINE_BREAK 17

struct ELFCNTR {
	int nullcntr;
        int line;
        int i;
};

typedef struct {
	char sname[6];
	int sections;
	int addrlen;
        int addr;
	struct ELFCNTR counters;
} ELFDATA;


int parse(char *obj_file,int exec) {
	ELFDATA *elf;
	FILE *obj;
	Elf64_Ehdr ehdr;
	Elf64_Shdr *shdr;

	if((obj=fopen(obj_file, "r+b")) == NULL) {
		printf("[*] Unable to open %s! Quitting.\n", obj_file);
		return -1;
	}

	printf("[*] Examining %s...\n", obj_file);
	fread(&ehdr,sizeof(ehdr), 1, obj);
	if(strncmp(ehdr.e_ident,ELFMAG,4) != 0) {
		printf("[*] %s is not a valid ELF object file!\n", obj_file);
		return -1;
	} 

	printf("[*] e_ident = 0x7f+ELF, continuing.\n");
		
	/*
	 * Complicated little process here *har* *har*.
         * - first we loop through the sections finding .text
	 * - get size and address of .text section
	 * - seek to offest of the data and copy it to a buffer
	 * - display shellcode in C format
	 * - then execute shellcode
	*/
	shdr = (Elf64_Shdr *)malloc(sizeof(shdr));
	elf  = (ELFDATA *)malloc(sizeof(ELFDATA));
	elf->addrlen = 0;
        elf->addr    = 0;
        elf->counters.nullcntr  = 0;
        elf->counters.line      = 0;
        elf->counters.i         = 0;

	fseek(obj, ehdr.e_shoff, SEEK_SET);
	fread(shdr, sizeof(*shdr), ehdr.e_shnum, obj);

	while(elf->sections++ < ehdr.e_shnum) {			
		
		fseek(obj, shdr[ehdr.e_shstrndx].sh_offset + shdr[elf->sections].sh_name, SEEK_SET);
		fgets(elf->sname, 6, obj);
		
		if((strncmp(elf->sname, ".text", 5)) == 0) {
			elf->addr = shdr[elf->sections].sh_offset;
			elf->addrlen = shdr[elf->sections].sh_size;
				
			printf("[*] Found .text section at address 0x%08x with length of %d bytes.\n", elf->addr, elf->addrlen);
			printf("[*] Dumping shellcode.\n");
		
			/*
			 * sh_offset is the offset of the section data from the beginning
                         * of the file so we seek to the beginning THEN the offset
			*/
			fseek(obj, 0L, SEEK_SET);
			fseek(obj, shdr[elf->sections].sh_offset, SEEK_SET);

			unsigned char obj_data[elf->addrlen + 1];	
		
			fgets(obj_data, elf->addrlen + 1, obj);
			while(elf->counters.i <= elf->addrlen - 1) {

				if(strlen(obj_data) <= elf->addrlen - 1) {
     					if(obj_data[elf->counters.i] == 0) {
               					elf->counters.nullcntr++;
					}
     				}
					
				if(elf->counters.line >= LINE_BREAK) {
					printf("\n");
					elf->counters.line = 0;
				}

          			printf("\\x%02x", obj_data[elf->counters.i++]);
				elf->counters.line++;
			}
				
			printf("\n");
			close(obj);	
			
			if(elf->counters.nullcntr > 0) {
				printf("[*] WARNING: Detected %d null bytes!\n", elf->counters.nullcntr);
			}

			if(exec == 1) {
				executecode(obj_data, elf->addrlen);
			}
				
		}
	}

	return 0;
}

int executecode(unsigned char *exshellcode, int shellen) {
	unsigned char *shellcode;

	printf("[*] Mapping and copying %d bytes of shellcode to memory.\n", shellen);	
	
	shellcode = (unsigned char *)mmap(0, shellen - 1, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	memcpy(shellcode, exshellcode, shellen);
	
	printf("[*] Executing shellcode at address %p.\n", shellcode);

	( *(void(*) ()) shellcode)();

	return 0;
}

int usage(char *pname) {
	 printf("Linux 64-Bit mmap based shellcode loader by Travis \"rjkall\".\n");
	 printf("usage: %s <file> [-e]\n", pname);
         printf("<file>  ELF object file.\n");
         printf("-e      Execute shellcode.\n\n");
	 printf("Default will just dump shellcode in C format.\n");
}

int main(int argc, char *argv[]) {
	switch(argc) {
		case 2:
			parse(argv[1],0);
			break;
		case 3:
			if((strncmp(argv[2], "-e", 2)) == 0) {
                        	parse(argv[1], 1);
                	} else {
                        	usage(argv[0]);
			}
                	break;
		default:
			usage(argv[0]);
	}

	return 0;
}	
