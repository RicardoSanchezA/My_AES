
#include "my_aes.h"

int main(int argc, char** argv) {
  MyAES my_aes(128, "key.txt", "input.txt", "output.txt");

  my_aes.GenerateKeys();
  my_aes.Encrypt();

  return 0;
}