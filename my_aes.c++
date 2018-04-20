#include "my_aes.h"
#include "lookup_tables.h"

// MyAES Constructors
MyAES::MyAES() {}
MyAES::MyAES(const int& _key_size,
             const std::string& _key_file,
             const std::string& _input_file,
             const std::string& _output_file) {
  // Open all required files
  key_file.open(_key_file);
  in_file.open(_input_file);
  out_file.open(_output_file);
  // Initialize vector where we'll store expanded keys
  expanded_keys = std::vector<byte>(key_size == 128 ? 176 : 240);
}

// Pricate/Helper Methods
void MyAES::CheckPadding() {
  int row, col;
  row = col = 3;
  pad_size = 0;
  while (col >= 0 && data[row][col] == 0) {
    --row;
    if (row < 0) {
      row = 3;
      --col;
    }
    ++pad_size;
  }
}
void MyAES::FillData() {
  char c;
  int row, col;
  row = col = data_size = 0;
  // Read data from input file (one char/byte at a time)
  while (data_size < 16 && in_file.get(c)) {
    data[row][col] = c;
    ++row;
    if (row > 3) {
      row = 0;
      ++col;
    }
    ++data_size;
  }
  if (data_size > 0) {
    // If the data matrix is not full, fill
    // in the remaining spots with zeroes.
    while (data_size < 16) {
      data[row][col] = 0;
      ++row;
      if (row > 3) {
        row = 0;
        ++col;
      }
      ++data_size;
    }
  }
}
void MyAES::SubBytes() {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i][j] = s[data[i][j]];
    }
  }
}
void MyAES::InvSubBytes() {
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i][j] = inv_s[data[i][j]];
    }
  }
}
void MyAES::ShiftLeft(byte* row) {
  byte temp = row[0];
  for (int i = 0; i < 3; ++i)
    row[i] = row[i + 1];
  row[3] = temp;
}
void MyAES::ShiftRows() {
  for (int i = 1; i <= 3; ++i) {
    for (int j = 1; j <= i; ++j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::InvShiftRows() {
  for (int i = 1; i <= 3; ++i) {
    for (int j = 3; j >= i; --j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::MixColumns() {
  byte temp[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      for (int k = 0; k < 4; ++k) {
        int a = galois_matrix[j][k];
        byte b = data[k][i];
        if (a == 1) temp[j][i] ^= b;
        if (a == 2) temp[j][i] ^= two[b];
        if (a == 3) temp[j][i] ^= three[b];
      }
    }
  }
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i][j] = temp[i][j];
    }
  }
}
void MyAES::InvMixColumns() {
  byte temp[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      for (int k = 0; k < 4; ++k) {
        int a = inv_galois_matrix[j][k];
        byte b = data[k][i];
        if (a == 9) temp[j][i] ^= nine[b];
        if (a == 11) temp[j][i] ^= eleven[b];
        if (a == 13) temp[j][i] ^= thirteen[b];
        if (a == 14) temp[j][i] ^= fourteen[b];
      }
    }
  }
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      data[i][j] = temp[i][j];
    }
  }
}
void MyAES::GenerateKeyHelper(byte in[], int i) {
  ShiftLeft(in);
  for (int a = 0; a < 4; ++a) {
    in[a] = s[in[a]];
  }
  in[0] ^= rcon[i];
}
void MyAES::AddRoundKey(const int& round) {
  for (int i = 0, k = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j, ++k) {
      data[j][i] = data[j][i] ^ expanded_keys[round*16 + k];
    }
  }
}
void MyAES::StoreData() {
  CheckPadding();
  for (int i = 0, k = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j, ++k) {
      if (k < data_size - pad_size) out_file << data[j][i];
    }
  }
}

// Public Methods
void MyAES::GenerateKeys() {
  int n = (key_size == 128 ?  16 :  32);
  byte temp[4];
  char x;
  // Get first 'n' bytes from the original key
  for (int i = 0; i < n && key_file.get(x); ++i) {
    expanded_keys[i] = x;
  }
  // Fill the remaining bytes using the specified iterative process
  for (int processed_bytes = n, it = 1; processed_bytes < expanded_keys.size();
       processed_bytes += 4) {
    // Assign the value of the previous 4 bytes to 'temp'. We are
    // going to build the next 4 bytes of our expanded key in 'temp'.
    for (int i = 0; i < 4; ++i) {
      temp[i] = expanded_keys[processed_bytes + i - 4];
    }
    // Every 'n' bytes (size each key) we want to re-
    // generate the core part of the next expanded key.
    if (processed_bytes % n == 0) {
      GenerateKeyHelper(temp, it);
      ++it;
    }
    // We need to use the fixed s-table for 256-bit keys to make a substitution
    if (key_size == 256 && processed_bytes % n == (n >> 1)) {
      for (int i = 0; i < 4; ++i) {
        temp[i] = s[temp[i]];
      }
    }
    // Last Setp: XOR with expanded_keys that are 'n' bytes behind and
    // finally store the temp key that we've built so far in expanded_keys.
    for (int i = 0; i < 4; ++i) {
      temp[i] ^= expanded_keys[processed_bytes + i - n];
      expanded_keys[processed_bytes + i] = temp[i];
    }
  }
}
void MyAES::Encrypt() {
  int num_rounds = (key_size == 128) ? 10 : 14;
  while (1) {
    // Get next 16 bytes of data from input file
    FillData();
    // Stop if no data was extracted (i.e. EOF)
    if (data_size == 0) break;
    // Do iterative process to encrypt data:
    AddRoundKey(0);
    int round;
    for (round = 1; round < num_rounds; ++round) {
      SubBytes();
      ShiftRows();
      MixColumns();
      AddRoundKey(round);
    }
    SubBytes();
    ShiftRows();
    AddRoundKey(round);
    // Store encrypted data to output file
    StoreData();
  }
}
void MyAES::Decrypt() {
  while (1) {
    int round = (key_size == 128) ? 10 : 14;
    // Get next 16 bytes of data from input file
    FillData();
    // Stop if no data was extracted (i.e. EOF)
    if (data_size == 0) break;
    // Do the inverse of the iterative process to decrypt:
    AddRoundKey(round--);
    InvShiftRows();
    InvSubBytes();
    for (; round > 0; --round) {
      AddRoundKey(round);
      InvMixColumns();
      InvShiftRows();
      InvSubBytes();
    }
    AddRoundKey(round);
    // Store decrypted data to output file
    StoreData();
  }
}

// MyAES Destructor
MyAES::~MyAES() {
  // Close all files
  key_file.close();
  in_file.close();
  out_file.close();
}
