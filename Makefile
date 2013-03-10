CC=gcc
FILE=shelloader

all:
	$(CC) -o $(FILE) shelloader.c
clean:
	rm -rf shelloader.o shelloader
