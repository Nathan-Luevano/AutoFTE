/*
 * vuln-demo: a deliberately vulnerable target for exercising AutoFTE.
 *
 * It reads one file (given as argv[1]) and dispatches on the FIRST byte
 * ("the marker") to one of four independent, genuinely distinct bugs. The
 * rest of the file is the payload for whichever bug the marker selects.
 * This lets a fuzzer (or a pre-generated crash corpus, see ../crashes/)
 * reach all four bugs from the same binary, so a triage tool has more than
 * one real root cause to collapse a pile of crashes into -- see
 * the project methodology ("THE HOOK") for why that matters.
 *
 *   marker '1' -> stack buffer overflow   (vuln_stack_overflow)
 *   marker '2' -> heap buffer overflow    (vuln_heap_overflow)
 *   marker '3' -> use-after-free          (vuln_use_after_free)
 *   marker '4' -> NULL pointer dereference (vuln_null_deref)
 *   anything else -> no bug is reached; the program just exits cleanly
 *
 * Every bug here is intentional and exists purely to give AutoFTE (and
 * anyone poking at this with gdb/AFL++ themselves) something real to find.
 * Don't reuse this code, or the Makefile's mitigation-disabling flags, in
 * anything you'd actually ship.
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Bug 1: stack buffer overflow.
 *
 * `buf` is 64 bytes on the stack. `strcpy` copies `payload` into it with
 * no length check at all, so any payload longer than 63 bytes (plus the
 * NUL terminator) overflows into whatever else lives on this stack frame
 * -- saved registers, the return address, etc.
 */
static void vuln_stack_overflow(const char *payload) {
  char buf[64];
  strcpy(buf, payload); /* no bounds check: classic unbounded strcpy */
}

/*
 * Bug 2: heap buffer overflow.
 *
 * `heap_buf` is a 64-byte heap allocation. `memcpy` writes `payload_len`
 * bytes into it -- `payload_len` comes straight from the input file, with
 * no check that it fits in the 64 bytes that were actually allocated. A
 * payload longer than 64 bytes writes past the allocation into adjacent
 * heap memory / allocator metadata.
 */
static void vuln_heap_overflow(const char *payload, size_t payload_len) {
  char *heap_buf = malloc(64);
  if (!heap_buf) {
    return;
  }
  memcpy(heap_buf, payload, payload_len); /* no bounds check on payload_len */
  heap_buf[0] = 'X'; /* touch it so the write above isn't optimized away */
  free(heap_buf);
}

/*
 * Bug 3: use-after-free.
 *
 * The allocation is deliberately larger than glibc's default mmap
 * threshold (128 KiB), so glibc's malloc hands it back via mmap() instead
 * of carving it out of the normal heap arena -- which means free() calls
 * munmap() and the pages are genuinely unmapped immediately, not just
 * marked free in an arena that's still resident. That makes the
 * use-after-free write below reliably SIGSEGV even on the plain,
 * non-ASan build, not just under AddressSanitizer (which would also
 * catch this instantly via its quarantine/redzone poisoning, at any
 * size).
 */
#define UAF_ALLOC_SIZE (256 * 1024)

static void vuln_use_after_free(const char *payload, size_t payload_len) {
  char *heap_buf = malloc(UAF_ALLOC_SIZE);
  if (!heap_buf) {
    return;
  }
  memset(heap_buf, 0, UAF_ALLOC_SIZE);
  free(heap_buf);

  /* classic use-after-free: write attacker-controlled data through a
   * pointer to memory that has already been returned. */
  size_t n = payload_len < 16 ? payload_len : 16;
  memcpy(heap_buf, payload, n);
}

/*
 * Bug 4: NULL pointer dereference.
 *
 * `lookup_record` only returns a non-NULL pointer for the exact 4-byte
 * magic value "OKOK" at the start of the payload -- something a random
 * fuzzer input (or our pre-generated crash corpus) essentially never
 * produces by chance, so this path reliably dereferences NULL.
 */
static const char *lookup_record(const char *payload, size_t payload_len) {
  if (payload_len >= 4 && memcmp(payload, "OKOK", 4) == 0) {
    return payload;
  }
  return NULL; /* the common case: nothing found */
}

static void vuln_null_deref(const char *payload, size_t payload_len) {
  const char *record = lookup_record(payload, payload_len);
  putchar(record[0]); /* NULL deref whenever lookup_record returned NULL */
}

int main(int argc, char **argv) {
  char buffer[1024];

  if (argc != 2) {
    printf("Usage: %s <input_file>\n", argv[0]);
    return 1;
  }

  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror("Failed to open input file");
    return 1;
  }

  ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
  close(fd);

  if (bytes_read <= 0) {
    printf("Failed to read input or empty file\n");
    return 1;
  }

  buffer[bytes_read] = '\0';

  /* First byte selects which bug to reach; the rest of the file is that
   * bug's payload. */
  char marker = buffer[0];
  const char *payload = buffer + 1;
  size_t payload_len = (size_t)bytes_read - 1;

  switch (marker) {
    case '1':
      vuln_stack_overflow(payload);
      break;
    case '2':
      vuln_heap_overflow(payload, payload_len);
      break;
    case '3':
      vuln_use_after_free(payload, payload_len);
      break;
    case '4':
      vuln_null_deref(payload, payload_len);
      break;
    default:
      /* Unrecognized marker: no bug is reached, nothing crashes. */
      break;
  }

  printf("Program executed successfully\n");
  return 0;
}
