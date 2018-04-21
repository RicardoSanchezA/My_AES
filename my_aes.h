#ifndef MY_AES_H
#define MY_AES_H

#include <fstream>
#include <vector>

#define DATA_SIZE 16
#define DATA_DIMENSION 4
#define EXPANDED_KEY_SIZE 16

typedef uint8_t byte;

class MyAES {
 public:
  // Constructors
  MyAES();
  MyAES(const uint16_t& _key_size,
        const std::string& _key_file,
        const std::string& _input_file,
        const std::string& _output_file,
        const bool& _cbc_mode);
  // Public Methods
  void GenerateKeys();
  void Encrypt();
  void Decrypt();
  // Destructor
  ~MyAES();

 private:
  // Private/Helper Methods
  void CheckPadding();
  void LoadInitVector();
  void LoadData();
  void SubBytes(const uint8_t* table);
  void ShiftLeft(byte* in);
  void ShiftRows();
  void InvShiftRows();
  void MixColumns(const uint8_t (&matrix)[DATA_DIMENSION][DATA_DIMENSION]);
  void StoreData();
  void GenerateKeyCore(byte* in, const uint8_t& i);
  void CopyData(std::vector<byte>& v);
  void XorData(const std::vector<byte>& v, const uint8_t& offset = 0);
  void Error(const char* msg);
  // Private Data
  byte data[DATA_DIMENSION][DATA_DIMENSION];
  std::vector<byte> expanded_keys;
  std::vector<byte> cbc_buffer;
  uint16_t key_size;
  uint8_t pad_size;
  uint8_t data_size;
  bool cbc_mode;
  std::ifstream key_file;
  std::ofstream out_file;
  std::ifstream in_file;
};

#endif
