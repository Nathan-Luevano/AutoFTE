CC ?= gcc
LOCAL_FLAGS ?= -O0 -g -fno-stack-protector -no-pie -z execstack
TARGET ?= target

.PHONY: all afl clean

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(LOCAL_FLAGS) -o $(TARGET) vuln.c

afl: vuln.c
	afl-gcc $(LOCAL_FLAGS) -o $(TARGET) vuln.c

clean:
	rm -f $(TARGET) target_asan core core.*
