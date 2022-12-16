CC=gcc
CXX=g++
CFLAGS=-Wall -Werror -g

TARGETS=trace-parser

All: $(TARGETS)

trace-parser: trace-parser.o
	$(CXX) $(CFLAGS) -o $@ $<

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o

distclean: clean
	rm -f $(TARGETS)
