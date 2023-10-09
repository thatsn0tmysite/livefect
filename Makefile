#gcc livefect.c -o livefect -lcapstone 
default: livefect

livefect:
	gcc *.c /usr/lib/libZydis.so -Wall -o livefect
	strip livefect

static:
	gcc *.c /usr/lib/libZydis.so -static -Wall -o livefect
	strip livefect

victim:
	cd examples/victim && make
	cd ../../

clean:
	rm -f *.o *.so
	rm -f livefect
	rm -f examples/victim/victim
	rm -f examples/victim/*.o  examples/victim/*.so