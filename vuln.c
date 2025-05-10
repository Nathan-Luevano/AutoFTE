#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void vuln(char *input) {
  char buf[64];
  strcpy(buf, input);
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
  
  vuln(buffer);
  
  printf("Program executed successfully\n");
  return 0;
}