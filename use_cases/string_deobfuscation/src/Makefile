
all: _strdeobfus strdeobfus

_strdeobfus.o: _strdeobfus.c
	gcc -c -o _strdeobfus.o _strdeobfus.c  

_strdeobfus: _strdeobfus.o
	gcc -o _strdeobfus _strdeobfus.o

strdeobfus.o: _strdeobfus.c
	gcc -c -o strdeobfus.o _strdeobfus.c 

strdeobfus: _strdeobfus
	python3 ./encrypt_strings.py

clean: 
	rm -f _strdeobfus strdeobfus strdeobfus2 *.o encrypted_data decrypted_data




