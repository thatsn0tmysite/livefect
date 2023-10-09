default: victim

victim:
	gcc -shared external_so.c -o victim.so 
	gcc victim.c -o victim

clean:
	rm -f *.o *.so
	rm -f victim