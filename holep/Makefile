#GCC = gcc
GCC = arm-mozart-linux-gcc
SRC = main.c
INCLUDE = 
LIB = 
LDFLAG = -lpthread
EXEC = holep

all:
	$(GCC) -o $(EXEC) $(SRC) $(INCLUDE) $(LIB) $(LDFLAG)
	@cp -f $(EXEC) ~/i2k/initrd/nfsroot
	@sync

gdb:
	$(GCC) -g -o $(EXEC) $(SRC) $(INCLUDE) $(LIB) $(LDFLAG)
	@cp -f $(EXEC) ~/i2k/initrd/nfsroot
	@sync

clean:
	rm $(EXEC)
