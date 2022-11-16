CC=gcc
CXX=g++
CFLAGS=-Wall -Werror -g

TARGETS=proj4

All: $(TARGETS)

proj4: proj4.o
	$(CXX) $(CFLAGS) -o $@ $<

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
