#include <iostream>

#include "my_aes.h"
#include "lookup_tables.h"

// MyAES Constructors
MyAES::MyAES() : data(),
             key_size(), 
             key_file(), 
             in_file(), 
             out_file() {}
MyAES::MyAES(const int& _key_size,
             const std::string& _key_file,
             const std::string& _input_file,
             const std::string& _output_file) : 
             data(),
             key_size(_key_size), 
             key_file(), 
             in_file(), 
             out_file() {
               key_file.open(_key_file);
               in_file.open(_input_file);
               out_file.open(_output_file); 
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
void MyAES::ShiftRow(const int& row) {
  byte temp = data[row][0];
  data[row][0] = data[row][1];
  data[row][1] = data[row][2];
  data[row][2] = data[row][3];
  data[row][3] = temp;
}
void MyAES::ShiftRows() {
  for(int i = 1; i <= 3; ++i) {
    for(int j = 1; j <= i; ++j) {
      ShiftRow(i);
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
void MyAES::GenerateKeys() {

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
}