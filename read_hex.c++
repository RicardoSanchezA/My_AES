#include <fstream>

int main(int argc, char** argv) {
  if (argc > 1) {
    std::ifstream file;
    file.open(argv[1]);
    if (file.is_open()) {
      char c;
      while (file.get(c)) {
        uint8_t t = c;
        printf("%02x ", t);
      }
      printf("\n");
      file.close();
    }
  }
  return 0;
}
