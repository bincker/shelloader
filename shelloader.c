/* shelloader.c - Linux 64-Bit mmap based shell code loader
 *-------------------------------------------------------------------------
 * pass it your object file and it will display and execute the shellcode
 * date 3/8/2013
 * author Travis "rjkall" <rjtravis@hushmail.com>
 * http://www.blackhatlibrary.net
 *
 * UPDATES:
 * - Error checking, variable fixes, usage, check entire e_ident now
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
#include <shelloader.h>

int parse(char *obj_file, int exec) {
	
	if((obj=fopen(obj_file, "r+b")) == NULL) {
		fprintf(stderr,"%s[*]%s Unable to open %s, %s.\n", RED, STOP, obj_file, strerror(errno));
		return -1;
	}

	printf("%s[*]%s Examining %s...\n", GRAY, STOP, obj_file);
	fread(&ehdr,sizeof(ehdr), 1, obj);
	if(strncmp(ehdr.e_ident,ELFMAG,4) != 0) {
		printf("%s[*]%s %s is not a valid ELF object file!\n", RED, STOP, obj_file);
		return -1;
	} 

	printf("%s[*]%s e_ident = 0x7f+ELF, continuing.\n", GRAY, STOP);
		
	/*
	 * Complicated little process here *har* *har*.
         * - first we loop through the sections finding .text
	 * - get size and address of .text section
	 * - seek to offest of the data and copy it to a buffer
	 * - display shellcode in C format
	 * - then execute shellcode
	*/
	shdr = (Elf64_Shdr *)malloc(sizeof(shdr));
	assert(shdr);
	elf  = (ELFDATA *)malloc(sizeof(ELFDATA));
	assert(elf);

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
		
		if((strncmp(elf->sname, CODE_SECTION, 5)) != 0) {
			continue;
		}

		elf->addr = shdr[elf->sections].sh_offset;
		elf->addrlen = shdr[elf->sections].sh_size;
				
		printf("%s[*]%s Found '.text' section at address 0x%08x with length of %d bytes.\n", GRAY, STOP, elf->addr, elf->addrlen);
		printf("%s[*]%s Dumping shellcode.\n", GRAY, STOP);
		
		/*
		 * sh_offset is the offset of the section data from the beginning
                 * of the file so we seek to the beginning THEN the offset
		*/
		fseek(obj, 0L, SEEK_SET);
		fseek(obj, shdr[elf->sections].sh_offset, SEEK_SET);

		unsigned char obj_data[elf->addrlen + 1];	
		
		fgets(obj_data, elf->addrlen + 1, obj);
		printf("\nshellcode {%s\n\t", BLUE);
		while(elf->counters.i <= elf->addrlen - 1) {

			if(strlen(obj_data) <= elf->addrlen - 1) {
   				if(obj_data[elf->counters.i] == 0) {
               				elf->counters.nullcntr++;
				}
     			}
					
			if(elf->counters.line >= LINE_BREAK) {
				printf("\n\t");
				elf->counters.line = 0;
			}

          		printf("\\x%02x",obj_data[elf->counters.i++]);
			elf->counters.line++;
		}
				
		printf("%s\n}\n\n", STOP);
		close(obj);	
	
		if(elf->counters.nullcntr > 0) {
			printf("%s[*] WARNING:%s Detected %d null bytes!\n", RED, STOP, elf->counters.nullcntr);
		}

		if(exec == 1) {
			executecode(obj_data, elf->addrlen);
		}			

	}
	
	return 0;
}

int executecode(unsigned char *exshellcode, int shellen) {
	unsigned char *shellcode;

	printf("%s[*]%s Mapping and copying %d bytes of shellcode to memory.\n", GRAY, STOP, shellen);	
	
	shellcode = (unsigned char *)mmap(0, shellen, MMAP_PARAMS, -1, 0);
	if(shellcode == MAP_FAILED) {
		fprintf(stderr,"%s[*]%s mmap error, %s\n", RED, STOP,strerror(errno));
		return -1;
	}
	memcpy(shellcode, exshellcode, shellen);
	
	printf("%s-->%s Executing shellcode at address %p.\n", GRAY, STOP, shellcode);
	( *(void(*) ()) shellcode)();

	return 0;
}
				

int usage(char *pname) {
	 printf("usage: %s <object-file> [-e]\n", pname);
         printf("<object-file>  ELF object file.\n");
         printf("-e             OPTIONAL: Execute shellcode.\n\n");
	 printf("Default will just dump shellcode in C format.\n");
}

int main(int argc, char *argv[]) {
	printf("Linux 64-Bit mmap based shellcode loader by Travis \"rjkall\".\n");
	printf("Bugs, requests to <rjtravis@hushmail.com>\n");
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
