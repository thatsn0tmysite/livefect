#gcc livefect.c -o livefect -lcapstone 
default: livefect

livefect:
	gcc livefect.c /usr/lib/libZydis.so -Wall -o livefect
	strip livefect

static:
	gcc livefect.c /usr/lib/libZydis.so -static -Wall -o livefect
	strip livefect

victim:
	gcc -shared external_so.c -o victim.so 
	gcc victim.c -o victim

clean:
	rm -f *.o *.so
	rm -f livefect
	rm -f victim