/* shelloader.h
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

#ifndef shelloader_H
#define shelloader_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <elf.h>


#define MMAP_PARAMS PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS
#define LINE_BREAK   18
#define CODE_SECTION ".text"

#define BLUE "\033[0;33m"
#define GRAY "\033[0;37m"
#define RED  "\033[1;31m"
#define STOP "\033[1;0m"

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


int parse(char *obj_file, int exec);
int executecode(unsigned char *exshellcode, int shellen);
int usage(char *pname);

ELFDATA *elf;
FILE *obj;
Elf64_Ehdr ehdr;
Elf64_Shdr *shdr;

#endif
