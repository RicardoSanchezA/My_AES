#ifndef MY_AES_H
#define MY_AES_H

#include <fstream>
#include <vector>

typedef uint8_t byte;

class MyAES {
 public:
  // Constructors
  MyAES();
  MyAES(const int& _key_size,
        const std::string& _key_file,
        const std::string& _input_file,
        const std::string& _output_file);
  // Public Methods
  void GenerateKeys();
  void Encrypt();
  void Decrypt();
  // Destructor
  ~MyAES();

 private:
  // Private/Helper Methods
  void CheckPadding();
  void FillData();
  void SubBytes();
  void InvSubBytes();
  void ShiftLeft(byte *in);
  void ShiftRows();
  void InvShiftRows();
  void MixColumns();
  void InvMixColumns();
  void AddRoundKey(const int& round);
  void StoreData();
  void GenerateKeyHelper(byte* in, int i);
  // Private Data
  byte data[4][4];
  std::vector<byte> expanded_keys;
  int key_size;
  int pad_size;
  int data_size;
  std::ifstream key_file;
  std::ofstream out_file;
  std::ifstream in_file;
};

#endif
