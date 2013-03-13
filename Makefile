# shelloader
# Linux 64-bit mmap based shellcode loader
# Release 3/8/13
# Travis "rjkall"
# http:///github.com/rjkall


CC=gcc
INCLUDE = -I./include
NAME=shelloader

all:
	$(CC) -o $(NAME) $(INCLUDE) shelloader.c
clean:
	rm -rf shelloader.o $(NAME)
