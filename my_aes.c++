#include <iostream>

#include "my_aes.h"
#include "lookup_tables.h"

// MyAES Constructors
MyAES::MyAES() : data(),
	           expanded_keys(),
             key_size(),
             pad_size(0),
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
             pad_size(0),
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
  row = col = pad_size = 0;
  while (in_file >> c && pad_size < 16) {
    data[row][col] = c;
    ++row;
    ++pad_size;
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
  for(int i = 0; i < 4; ++i) {
    for(int j = 0; j < 4; ++j) {
      int num = galois_matrix[i][j];
      if (num == 2) {
        data[i][j] = two[data[i][j]];
      }
      else if (num == 3) {
        data[i][j] = three[data[i][j]];
      }
      else if (num == 9) {
        data[i][j] = nine[data[i][j]];
      }
      else if (num == 11) {
        data[i][j] = eleven[data[i][j]];
      }
      else if (num == 13) {
        data[i][j] = thirteen[data[i][j]];
      }
      else if (num == 14) {
        data[i][j] = fourteen[data[i][j]];
      }
    }
  }
}
void MyAES::GenerateKeyCore(byte in[], int i) {
  ShiftLeft(in);
  for(int a = 0; a < 4; ++a)
    in[a] = s[in[a]];

  in[0] ^= rcon[i];
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

// Public Methods
void MyAES::Encrypt() {
  std::cout << "Fill 4x4 Array:\n";
  FillData();
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

  printf("\n");
}
void MyAES::GenerateKeys() {
  int n = (key_size == 256 ? 32 : 16);
  int b = (key_size == 256 ? 240 : 176);
  byte temp[4];
  // Get first 'n' bytes from the original key
  {
    byte x;
    for(int i = 0; i < n && key_file >> x; ++i) {
      expanded_keys[i] = x;
    }
  }

  // Fill in the remaining bytes
  for(int processed_bytes = n, it = 1; processed_bytes < b; processed_bytes += 4) {
    // Assign the value of previous 4 bytes to 'temp'
    for(int i = 0; i < 4; ++i) {
      temp[i] = expanded_keys[processed_bytes + i - 4];
    }

    // Every 'n' bytes (size of each expanded key) we want to
    // re-generate the core part for the next expanded key.
    if (processed_bytes % n == 0) {
      GenerateKeyCore(temp, it);
      ++it;
    }

    // We need to use the s-table for 256-bit keys to make a substitution.
    if (key_size == 256 && processed_bytes % n == (n >> 1)) {
      for(int i = 0; i < 4; ++i)
        temp[i] = s[temp[i]];
    }
    
    // Last Setp: XOR with bytes that are 'n' bytes behind in 'expended_keys'. 
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