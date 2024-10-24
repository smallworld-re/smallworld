
all: strobfus strdeobfus

strobfus: strobfus.o
	gcc -o strobfus strobfus.o

strobfus.o: strdeobfus.o
	gcc -c -o strobfus.o strdeobfus.c

strdeobfus.o: strdeobfus.c
	gcc -c -o strdeobfus.o strdeobfus.c -D DEOBFS 

strdeobfus: strdeobfus.o
	gcc -o strdeobfus strdeobfus.o





clean: 
	rm -f strobfus strdeobfus *.o



