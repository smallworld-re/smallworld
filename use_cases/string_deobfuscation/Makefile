
all: _strdeobfus strdeobfus

_strdeobfus.o: _strdeobfus.c
	gcc -c -o _strdeobfus.o _strdeobfus.c  -D DEOBFS 

_strdeobfus: _strdeobfus.o
	gcc -o _strdeobfus _strdeobfus.o

strdeobfus.o: _strdeobfus.c
	gcc -c -o strdeobfus.o _strdeobfus.c # -D DEOBFS 


strdeobfus: _strdeobfus
	./_strdeobfus
	python ./encrypt_strings.py


clean: 
	rm -f _strdeobfus strdeobfus strdeobfus2 *.o new_strings encrypted_data decrypted_data




