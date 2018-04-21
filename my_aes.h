#ifndef MY_AES_H
#define MY_AES_H

#include <fstream>
#include <vector>

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
  void FillInitVector();
  void FillData();
  void SubBytes();
  void InvSubBytes();
  void ShiftLeft(byte *in);
  void ShiftRows();
  void InvShiftRows();
  void MixColumns();
  void InvMixColumns();
  void AddRoundKey(const uint8_t& round);
  void StoreData();
  void GenerateKeyHelper(byte* in, uint8_t i);
  void CopyData(std::vector<byte>& v);
  void XorDataCBC();
  void KeySizeError();
  // Private Data
  byte data[4][4];
  std::vector<byte> expanded_keys;
  std::vector<byte> init_vector;
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
