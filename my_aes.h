#ifndef MY_AES_H
#define MY_AES_H

#include <fstream>
#include <vector>

typedef uint8_t byte;

class MyAES {
  // Private Data
  byte data[4][4];
  std::vector<byte> expanded_keys;
  int key_size;
  int padding;
  int n;
  int b;
  std::ifstream key_file;
  std::ifstream out_file;
  std::ifstream in_file;
  // Private Methods
  void FillData();
  void SubBytes();
  void Rotate(byte *in);
  void ShiftRowLeft(const int& row);
  void ShiftRows();
  void MixColumns();
  void GenerateKeyCore(byte* in, int i);

  void PrintData();


public:
  // Constructors
  MyAES();
  MyAES(const int& _key_size,
        const std::string& _key_file,
        const std::string& _input_file,
        const std::string& _output_file);
  // Destructor
  ~MyAES();
  // Public Methods
  void Encrypt();
  void GenerateKeys();
};

#endif