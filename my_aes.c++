#include <iostream>

#include <iostream>
#include "my_aes.h"
#include "lookup_tables.h"

// MyAES Constructors
MyAES::MyAES() : data(),
             expanded_keys(),
             key_size(),
             data_size(0),
             key_file(), 
             in_file(), 
             out_file() {}
MyAES::MyAES(const int& _key_size,
             const std::string& _key_file,
             const std::string& _input_file,
             const std::string& _output_file) : 
             data(),
             expanded_keys(),
             key_size(_key_size), 
             data_size(0),
             key_file(), 
             in_file(), 
             out_file() {
               key_file.open(_key_file);
               in_file.open(_input_file);
               out_file.open(_output_file);
               expanded_keys = std::vector<byte>(key_size == 256 ? 240 : 176);
             }
// MyAES Destructor
MyAES::~MyAES() {
  key_file.close();
  in_file.close();
  out_file.close();
}

// Helper Methods
void MyAES::FillData() {
  char c;
  int row, col;
  row = col = data_size = 0;

  uint8_t hardcoded_input[] = {0x54,0x77,0x6f,0x20,0x4f,0x6e,0x65,0x20,0x4e,0x69,0x6e,0x65,0x20,0x54,0x77,0x6f};

  while (/*in_file >> c &&*/ data_size < 16) {
    c = hardcoded_input[data_size];
    printf("c: %x\n", c);
    data[row][col] = c;
    ++row;
    ++data_size;
    if (row == 4) {
      row = 0;
      ++col;
    }
  }
  printf("data_size: %d\n", data_size);
}
void MyAES::SubBytes() {
  for(int i = 0; i < 4; ++i) {
    for(int j = 0; j < 4; ++j) {
      data[i][j] = s[data[i][j]];
    }
  }
}
void MyAES::ShiftLeft(byte* row) {
  byte temp = row[0];
  for(int i = 0; i < 3; ++i)
    row[i] = row[i + 1];
  row[3] = temp;
}
void MyAES::ShiftRows() {
  for(int i = 1; i <= 3; ++i) {
    for(int j = 1; j <= i; ++j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::MixColumns() {
  byte temp[4][4];

  temp[0][0] = two[data[0][0]] ^ three[data[1][0]] ^ data[2][0] ^ data[3][0];
  temp[1][0] = data[0][0] ^ two[data[1][0]] ^ three[data[2][0]] ^ data[3][0];
  temp[2][0] = data[0][0] ^ data[1][0] ^ two[data[2][0]] ^ three[data[3][0]];
  temp[3][0] = three[data[0][0]] ^ data[1][0] ^ data[2][0] ^ two[data[3][0]];

  temp[0][1] = two[data[0][1]] ^ three[data[1][1]] ^ data[2][1] ^ data[3][1];
  temp[1][1] = data[0][1] ^ two[data[1][1]] ^ three[data[2][1]] ^ data[3][1];
  temp[2][1] = data[0][1] ^ data[1][1] ^ two[data[2][1]] ^ three[data[3][1]];
  temp[3][1] = three[data[0][1]] ^ data[1][1] ^ data[2][1] ^ two[data[3][1]];

  temp[0][2] = two[data[0][2]] ^ three[data[1][2]] ^ data[2][2] ^ data[3][2];
  temp[1][2] = data[0][2] ^ two[data[1][2]] ^ three[data[2][2]] ^ data[3][2];
  temp[2][2] = data[0][2] ^ data[1][2] ^ two[data[2][2]] ^ three[data[3][2]];
  temp[3][2] = three[data[0][2]] ^ data[1][2] ^ data[2][2] ^ two[data[3][2]];

  temp[0][3] = two[data[0][3]] ^ three[data[1][3]] ^ data[2][3] ^ data[3][3];
  temp[1][3] = data[0][3] ^ two[data[1][3]] ^ three[data[2][3]] ^ data[3][3];
  temp[2][3] = data[0][3] ^ data[1][3] ^ two[data[2][3]] ^ three[data[3][3]];
  temp[3][3] = three[data[0][3]] ^ data[1][3] ^ data[2][3] ^ two[data[3][3]];

  for(int i = 0; i < 4; ++i) {
    for(int j = 0; j < 4; ++j) {
      data[i][j] = temp[i][j];
    }
  }
}
void MyAES::GenerateKeyCore(byte in[], int i) {
  ShiftLeft(in);
  for(int a = 0; a < 4; ++a)
    in[a] = s[in[a]];

  in[0] ^= rcon[i];
}
void MyAES::AddRoundKey(const int& round) {
  for(int i = 0, k = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j, ++k) {
      data[j][i] = data[j][i] ^ expanded_keys[round*16 + k];
    }
  }
}
void MyAES::PrintData() {
  for(int i = 0; i < 4; ++i) {
    for(int j = 0; j < 4; ++j) {
      printf("%02x ", data[i][j]);
    }
    std::cout << "\n";
  }
  std::cout << "\n";
}
void MyAES::StoreData() {
  for(int i = 0, k = 0; i < 4; ++i) {
    for(int j = 0; j < 4 && k < data_size; ++j, ++k) {
      out_file << data[i][j];
      printf("%02x [%d,%d]", data[i][j], k, data_size);
    }
    std::cout << "\n";
  }
}

// Public Methods
void MyAES::Encrypt() {
  std::cout << "Fill 4x4 Array:\n";
  FillData();
  std::cout << "Round #0\n";
  std::cout << "AddRoundKey:\n";
  AddRoundKey(0);
  PrintData();

  int num_rounds = (key_size == 128) ? 10 : 14;
  int round;
  for(round = 1; round < num_rounds; ++round) {
    std::cout << "Round #" << round << "\n";
    PrintData();
    std::cout << "SubBytes:\n";
    SubBytes();
    PrintData();
    std::cout << "ShiftRows:\n";
    ShiftRows();
    PrintData();
    std::cout << "MixColumns:\n";
    MixColumns();
    PrintData();
    std::cout << "AddRoundKey:\n";
    AddRoundKey(round);
    PrintData();
    std::cout << "\n";
  }

  PrintData();
  std::cout << "SubBytes:\n";
  SubBytes();
  PrintData();
  std::cout << "ShiftRows:\n";
  ShiftRows();
  PrintData();
  std::cout << "AddRoundKey:\n";
  AddRoundKey(round);
  PrintData();

  StoreData();

  printf("\n");
}
void MyAES::GenerateKeys() {
  int n = 16;
  int b = 176;
  byte temp[4];
  byte x;

uint8_t original_key[] = {0x54,0x68,0x61,0x74,0x73,0x20,0x6d,0x79,0x20,0x4b,0x75,0x6e,0x67,0x20,0x46,0x75};

  // Read first 'n' bytes from the original key
  for(int i = 0; i < n /*&& key_file >> x*/; ++i) {
    //expanded_keys[i] = x;
    expanded_keys[i] = original_key[i];
    printf("x: %x\n", expanded_keys[i]);
  }

  // Fill in the first 176 bytes
  for(int processed_bytes = n, it = 1; processed_bytes < b; processed_bytes += 4) {
    // Assign the value of previous 4 bytes to 'temp'
    for(int i = 0; i < 4; ++i) {
      temp[i] = expanded_keys[processed_bytes + i - 4];
    }

    // Every 'n' bytes (size of expanded key) we want to
    // re-generate the core part of the next expanded key.
    if (processed_bytes % n == 0) {
      GenerateKeyCore(temp, it);
      ++it;
    }

    // We need to use the s-table for 256-bit keys to make a substitution.
    if (key_size == 256 && processed_bytes % n == (n >> 1)) {
      for(int i = 0; i < 4; ++i)
        temp[i] = s[temp[i]];
    }
    
    // Last Setp: XOR and store the 4-bytes worth of expanded keys that we generated so far. 
    for(int i = 0; i < 4; ++i) {
      expanded_keys[processed_bytes + i] = temp[i] ^ expanded_keys[processed_bytes + i - n];
    }
  }

  // Print for debugging
  int counter = 1;
  for(auto x : expanded_keys) {
    printf("%02x ", x);
    if (counter % 16 == 0)
      printf("\n");
    ++counter;
  }

}