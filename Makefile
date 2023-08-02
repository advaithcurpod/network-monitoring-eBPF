# Define the clang compiler and flags
CLANG = clang
CLANG_FLAGS = -O2 -target bpf -c

# Define the source and object files
SRC = map.c
OBJ = map.o

# Define the target interface and map name
IFACE = wlp5s0
MAP = ip_map

# Define the default rule to compile the program
all: $(OBJ)

# Define the rule to compile the source file
$(OBJ): $(SRC)
	$(CLANG) $(CLANG_FLAGS) $< -o $@

# Define the rule to load the program on the interface
load: $(OBJ)
	ip link set dev $(IFACE) xdp obj $(OBJ) sec xdp verbose

# Define the rule to unload the program from the interface
unload:
	ip link set dev $(IFACE) xdp off

# Define the rule to clean up the object file
clean:
	rm -f $(OBJ)