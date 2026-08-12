CC ?= gcc
LOCAL_FLAGS ?= -O0 -g -fno-stack-protector -no-pie -z execstack
TARGET ?= target

ASAN_CC ?= $(shell command -v clang >/dev/null 2>&1 && echo clang || echo $(CC))
ASAN_FLAGS ?= -fsanitize=address -g -O0
TARGET_ASAN ?= target_asan

.PHONY: all afl clean

all: $(TARGET)

$(TARGET): vuln.c
	$(CC) $(LOCAL_FLAGS) -o $(TARGET) vuln.c

afl: vuln.c
	afl-gcc $(LOCAL_FLAGS) -o $(TARGET) vuln.c

$(TARGET_ASAN): vuln.c
	$(ASAN_CC) $(ASAN_FLAGS) -o $(TARGET_ASAN) vuln.c

clean:
	rm -f $(TARGET) $(TARGET_ASAN) core core.*
