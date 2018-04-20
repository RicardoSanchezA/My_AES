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

  while (in_file.get(c) && data_size < 16) {
    data[row][col] = c;
    ++row;
    ++data_size;
    if (row == 4) {
      row = 0;
      ++col;
    }
  }
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
  byte temp[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};

  for(int i = 0; i < 4; ++i) {
    for(int j = 0; j < 4; ++j) {
      for(int k = 0; k < 4; ++k) {
        int a = galois_matrix[j][k];
        byte b = data[k][i];
        if (a == 1)
          temp[j][i] ^= b;
        if (a == 2)
          temp[j][i] ^= two[b];
        if (a == 3)
          temp[j][i] ^= three[b];
        if (a == 9)
          temp[j][i] ^= nine[b];
        if (a == 11)
          temp[j][i] ^= eleven[b];
        if (a == 13)
          temp[j][i] ^= thirteen[b];
        if (a == 14)
          temp[j][i] ^= fourteen[b];
      }
    }
  }

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
  std::cout << "ciphertext: ";
  for(int i = 0, k = 0; i < 4; ++i) {
    for(int j = 0; j < 4 && k < data_size; ++j, ++k) {
      out_file << data[j][i];
      printf("%02x ", data[j][i]);
    }
  }
  std::cout << "\n";
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
  }

  std::cout << "Round #" << round << "\n";
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
  int n = (key_size == 128 ?  16 :  32);
  int b = (key_size == 128 ? 176 : 240);
  byte temp[4];
  char x;

  // Get first 'n' bytes from the original key
  for(int i = 0; i < n && key_file.get(x); ++i) {
    expanded_keys[i] = x;
  }

  // Fill the remaining bytes using the specified iterative process
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