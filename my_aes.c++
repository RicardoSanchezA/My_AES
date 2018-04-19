#include <iostream>

#include "my_aes.h"
#include "lookup_tables.h"

// MyAES Constructors
MyAES::MyAES() : data(),
	           expanded_keys(),
             key_size(),
             padding(0),
             n(),
             b(), 
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
             padding(0),
             n(key_size == 128 ? 16 : 32),
             b(key_size == 128 ? 176 : 240),
             key_file(), 
             in_file(), 
             out_file() {
               key_file.open(_key_file);
               in_file.open(_input_file);
               out_file.open(_output_file);
               expanded_keys = std::vector<byte>(b);
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
  row = col = padding = 0;
  while (in_file >> c && padding < 16) {
    data[row][col] = c;
    ++row;
    ++padding;
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
void MyAES::ShiftRowLeft(const int& row) {
  byte temp = data[row][0];
  data[row][0] = data[row][1];
  data[row][1] = data[row][2];
  data[row][2] = data[row][3];
  data[row][3] = temp;
}
void MyAES::ShiftRows() {
  for(int i = 1; i <= 3; ++i) {
    for(int j = 1; j <= i; ++j) {
      ShiftRowLeft(i);
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
void MyAES::Rotate(byte *in) {
        byte a;
        a = in[0];
        for(int c=0;c<3;c++) 
                in[c] = in[c + 1];
        in[3] = a;
        return;
}
void MyAES::GenerateKeyCore(byte* in, int i) {
  Rotate(in);
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
  std::cout << "key_size: " << key_size << ", n: " << n << ", b: " << b << "\n";
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
  byte temp[4];
  byte x;
  // Read first 'n' bytes from the original key
  for(int i = 0; i < n && key_file >> x; ++i) {
    expanded_keys[i] = x;
  }

  // Fill in the first 176 bytes
  for(int processed_bytes = n, it = 1; processed_bytes < 176; processed_bytes += 4) {
    // Assign the value of previous 4 bytes to 'temp'
    for(int i = 0; i < 4; ++i) {
      temp[i] = expanded_keys[processed_bytes + i - 4];
    }

    // We only use the core if it's the first iteration
    if (processed_bytes % 16) {
      GenerateKeyCore(temp, it);
      ++it;
    }
    
    for(int i = 0; i < 4; ++i) {
      expanded_keys[processed_bytes + i] = temp[i] ^ expanded_keys[processed_bytes + i - n];
    }
  }

  int counter = 1;
  for(auto x : expanded_keys) {
    printf("%02x ", x);
    if (counter % 16 == 0)
      printf("\n");
    ++counter;
  }

}