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
install:
	install -D -m 755 ./$(NAME) /usr/bin/$(NAME)
remove:
	rm -fr /usr/bin/$(NAME)
clean:
	rm -rf shelloader.o $(NAME)
