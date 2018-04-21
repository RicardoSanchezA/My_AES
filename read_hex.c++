#include <iostream>
#include <fstream>

using namespace std;

int main(int argc, char** argv) {
  if (argc > 1) {
    ifstream file;
    file.open(argv[1]);
    if (file.is_open()) {
      char c;
      while (file.get(c)) {
        uint8_t t = c;
        printf("%02x ", t);
      }
      printf("\n");
    }
  }
  return 0;
}
