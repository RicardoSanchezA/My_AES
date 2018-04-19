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
  int data_size;
  std::ifstream key_file;
  std::ofstream out_file;
  std::ifstream in_file;
  // Private Methods
  void FillData();
  void SubBytes();
  void ShiftLeft(byte *in);
  void ShiftRows();
  void MixColumns();
  void AddRoundKey(const int& round);
  void StoreData();
  void GenerateKeyCore(byte* in, int i);
  // Used for debugging
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