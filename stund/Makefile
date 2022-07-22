#GCC = arm-hisiv100nptl-linux-gcc
GCC = gcc
SRC = main.c
INCLUDE = 
LIB = 
LDFLAG = -lpthread
EXEC = stund

all:
	$(GCC) -o $(EXEC) $(SRC) $(INCLUDE) $(LIB) $(LDFLAG)

gdb:
	$(GCC) -g -o $(EXEC) $(SRC) $(INCLUDE) $(LIB) $(LDFLAG)

clean:
	rm $(EXEC)
