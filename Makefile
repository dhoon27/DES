CC = gcc
CFLAGS = -c
TARGET = DES

$(TARGET): des_main.o utils.o des_cipher.o des_pad.o
	$(CC) des_main.o utils.o des_cipher.o des_pad.o -o $(TARGET)

des_main.o: des_main.c utils.h des_cipher.h des_param.h
	$(CC) $(CFLAGS) des_main.c

des_cipher.o: des_cipher.c des_cipher.h des_param.h des_pad.h utils.h
	$(CC) $(CFLAGS) des_cipher.c

des_pad.o: des_pad.c des_pad.h utils.h 
	$(CC) $(CFLAGS) des_pad.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) utils.c

clean: 
	rm *.o $(TARGET)