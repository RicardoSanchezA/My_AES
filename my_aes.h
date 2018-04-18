#ifndef MY_AES_H
#define MY_AES_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>

#include "lookup_tables.h"

typedef uint8_t byte;

int galois_matrix[4][4] = {{2,3,1,1}, {1,2,3,1}, {1,1,2,3}, {3,1,1,2}};
int inverse_galois_matrix[4][4] = {{14,11,13,9},{9,14,11,13},{13,9,14,11},{11,13,9,14}};

class MyAES {
  // Private Data
  byte data[4][4];
  std::vector<byte> expanded_keys;
  int key_size;
  int padding;
  std::ifstream key_file;
  std::ifstream out_file;
  std::ifstream in_file;
  // Private Methods
  void FillData();
  void SubBytes();
  void ShiftRow(const int& row);
  void ShiftRows();
  void MixColumns();
  void GenerateKeys();


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
};

#endif