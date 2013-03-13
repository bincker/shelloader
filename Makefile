CC=gcc
INCLUDE = -I./include
NAME=shelloader

all:
	$(CC) -o $(NAME) $(INCLUDE) shelloader.c
clean:
	rm -rf shelloader.o $(NAME)
