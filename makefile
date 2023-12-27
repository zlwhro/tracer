all: tracer fuzzhook.so

tracer: tracer.o hoonreadelf.o hoondebug.o
	gcc -o tracer tracer.o hoonreadelf.o hoondebug.o

tracer.o: tracer.c
	gcc -c tracer.c hoonreadelf.h hoondebug.h

hoonreadelf.o: hoonreadelf.c hoonreadelf.c
	gcc -c hoonreadelf.c hoonreadelf.h
hoondebug.o: hoondebug.c hoondebug.h
	gcc -c hoondebug.c hoondebug.h

fuzzhook.so: fuzzhook.c
	gcc -shared -fPIC -ldl -o fuzzhook.so fuzzhook.c	

clean:
	rm *.o *.gch *.so
	rm tracer
