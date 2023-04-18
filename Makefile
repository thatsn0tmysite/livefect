#gcc livefect.c -o livefect -lcapstone 
default: livefect

livefect:
	gcc livefect.c -lcapstone -Wall -o livefect
	strip livefect

static:
	gcc livefect.c -static -lcapstone -Wall -o livefect
	strip livefect

victim:
	gcc -shared external_so.c -o victim.so 
	gcc victim.c -o victim

clean:
	rm -f *.o *.so
	rm -f livefect
	rm -f victim