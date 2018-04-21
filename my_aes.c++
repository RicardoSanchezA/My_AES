#include "my_aes.h"
#include "lookup_tables.h"

// MyAES Constructors
MyAES::MyAES() {}
MyAES::MyAES(const uint16_t& _key_size,
             const std::string& _key_file,
             const std::string& _input_file,
             const std::string& _output_file,
             const bool& _cbc_mode) {
  // Set the key size
  key_size = _key_size;
  // Open all required files
  key_file.open(_key_file);
  in_file.open(_input_file);
  out_file.open(_output_file);
  // Verify that all files were opened correctly
  if (!key_file.is_open() || !in_file.is_open() || !out_file.is_open()) {
    fprintf(stderr, "Error: At least one of the files provided is invalid.\n");
    exit(-1);
  }
  // Set CBC mode flag
  cbc_mode = _cbc_mode;
  // Initialize vector where we'll store expanded keys
  expanded_keys = std::vector<byte>(key_size == 128 ? 176 : 240);
  // Initialize data structures used for CBC mode
  if (cbc_mode) {
    cbc_buffer = std::vector<byte>(16);
  }
}

// Private/Helper Methods
void MyAES::CheckPadding() {
  int8_t row, col;
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
void MyAES::LoadInitVector() {
  uint8_t i;
  char c;
  // The first 16 bytes of the key-file represent the
  // init. vector (whenever CBC mode is enabled).
  for (i = 0; i < 16 && key_file.get(c); ++i) {
    cbc_buffer[i] = c;
  }
  // Verify we read full 16 bytes of data from key file
  if (i != 16) KeySizeError();
}
void MyAES::LoadData() {
  char c;
  uint8_t row, col;
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
    // If the data matrix is partially full, then
    // fill in the remaining spots with zeros.
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
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      data[i][j] = s[data[i][j]];
    }
  }
}
void MyAES::InvSubBytes() {
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      data[i][j] = inv_s[data[i][j]];
    }
  }
}
void MyAES::ShiftLeft(byte* row) {
  byte temp = row[0];
  for (uint8_t i = 0; i < 3; ++i)
    row[i] = row[i + 1];
  row[3] = temp;
}
void MyAES::ShiftRows() {
  for (uint8_t i = 1; i <= 3; ++i) {
    for (uint8_t j = 1; j <= i; ++j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::InvShiftRows() {
  for (uint8_t i = 1; i <= 3; ++i) {
    for (uint8_t j = 3; j >= i; --j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::MixColumns() {
  byte temp[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      for (uint8_t k = 0; k < 4; ++k) {
        uint8_t a = galois_matrix[j][k];
        byte b = data[k][i];
        if (a == 1) temp[j][i] ^= b;
        if (a == 2) temp[j][i] ^= two[b];
        if (a == 3) temp[j][i] ^= three[b];
      }
    }
  }
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      data[i][j] = temp[i][j];
    }
  }
}
void MyAES::InvMixColumns() {
  byte temp[4][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      for (uint8_t k = 0; k < 4; ++k) {
        uint8_t a = inv_galois_matrix[j][k];
        byte b = data[k][i];
        if (a == 9) temp[j][i] ^= nine[b];
        if (a == 11) temp[j][i] ^= eleven[b];
        if (a == 13) temp[j][i] ^= thirteen[b];
        if (a == 14) temp[j][i] ^= fourteen[b];
      }
    }
  }
  for (uint8_t i = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j) {
      data[i][j] = temp[i][j];
    }
  }
}
void MyAES::GenerateKeyHelper(byte in[], const uint8_t& i) {
  ShiftLeft(in);
  for (uint8_t a = 0; a < 4; ++a) {
    in[a] = s[in[a]];
  }
  in[0] ^= rcon[i];
}
void MyAES::StoreData() {
  CheckPadding();
  for (uint8_t i = 0, k = 0; i < 4; ++i) {
    for (uint8_t j = 0; j < 4; ++j, ++k) {
      if (k < data_size - pad_size) out_file << data[j][i];
    }
  }
}
void MyAES::CopyData(std::vector<byte>& v) {
  for (uint8_t i = 0, k = 0; i < 4; ++i) { 
    for (uint8_t j = 0; j < 4; ++j, ++k) {
      v[k] = data[j][i];
    }
  }
}
void MyAES::XorData(const std::vector<byte>& v, const uint8_t& offset) {
  for (uint8_t i = 0, k = 0; i < 4; ++i) { 
    for (uint8_t j = 0; j < 4; ++j, ++k) {
      data[j][i] ^= v[k + offset];
    }
  }
}
void MyAES::KeySizeError() {
  fprintf(stderr, "Error: the key file provided is not large to span a key \
of %d-bits.\n", key_size);
  exit(-1);
}

// Public Methods
void MyAES::GenerateKeys() {
  // When CBC mode is enabled, the first 16 bytes of the key file are used 
  // uniquely for the init. vector (i.e. the user must assert that the key
  // (s)he wants to use should start 16 bytes after the beginning of their key-
  // file. The first 16 bytes of the keyfile must represent the init. vector).
  if (cbc_mode) LoadInitVector();

  uint8_t n = (key_size == 128 ?  16 :  32);
  byte temp[4];
  char x;
  // Get first 'n' bytes from the original key
  {
    uint8_t i;
    for (i = 0; i < n && key_file.get(x); ++i) {
      expanded_keys[i] = x;
    }
    // Verify that we actually read all bytes of key.
    if (i != n) KeySizeError();
  }
  // Generate expanded keys using the specified iterative process
  for (uint16_t processed_bytes = n, it = 1; 
       processed_bytes < expanded_keys.size(); processed_bytes += 4) {
    // Assign the value of the previous 4 bytes to 'temp'. We are
    // going to build the next 4 bytes of our expanded key in 'temp'.
    for (uint8_t i = 0; i < 4; ++i) {
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
      for (uint8_t i = 0; i < 4; ++i) {
        temp[i] = s[temp[i]];
      }
    }
    // Last Setp: XOR with expanded_keys that are 'n' bytes behind and
    // finally store the temp key that we've built so far in expanded_keys.
    for (uint8_t i = 0; i < 4; ++i) {
      temp[i] ^= expanded_keys[processed_bytes + i - n];
      expanded_keys[processed_bytes + i] = temp[i];
    }
  }
}
void MyAES::Encrypt() {
  // Get the appropriate number of rounds needed depending on key size
  uint8_t num_rounds = (key_size == 128) ? 10 : 14;
  while (1) {
    // Get next 16 bytes of data from input file
    LoadData();
    // Stop if no data was extracted (i.e. EOF)
    if (data_size == 0) break;
    // XOR the 16 bytes of data with whatever is in 'cbc_buffer'
    // 'cbc_buffer' initially holds the initialization vector.
    if (cbc_mode) XorData(cbc_buffer);
    
    // Do iterative process to encrypt data:
    uint8_t round = 0;
    // Add/XOR Round Key:
    XorData(expanded_keys, round*16);
    for (++round; round < num_rounds; ++round) {
      SubBytes();
      ShiftRows();
      MixColumns();
      //Add/XOR Round Key:
      XorData(expanded_keys, round*16);
    }
    SubBytes();
    ShiftRows();
    // Add/XOR Round Key:
    XorData(expanded_keys, round*16);

    // Store encrypted data to output file
    StoreData();
    // Copy the 16 bytes of cipher-text to 'cbc_buffer'
    if (cbc_mode) CopyData(cbc_buffer);
  }
}
void MyAES::Decrypt() {
  // 'temp' is only used for CBC mode; we initialize it to the
  // cbc_buffer, which initially holds the init. vector.
  std::vector<byte> temp(cbc_buffer);
  while (1) {
    // Copy whatever is in 'temp' into the cbc_buffer.
    if (cbc_mode) std::copy(temp.begin(), temp.end(), 
                            cbc_buffer.begin());
    // Get the appropriate number of rounds needed depending on key size
    uint8_t round = (key_size == 128) ? 10 : 14;
    // Get next 16 bytes of data from input file
    LoadData();
    // Stop if no data was extracted (i.e. EOF)
    if (data_size == 0) break;
    // Copy the 16 bytes of data into 'temp'
    if (cbc_mode) CopyData(temp);

    // Do the inverse of the iterative process to decrypt:
    // Add/XOR Round Key:
    XorData(expanded_keys, (round--)*16);
    InvShiftRows();
    InvSubBytes();
    for (; round > 0; --round) {
      // Add/XOR Round Key:
      XorData(expanded_keys, round*16);
      InvMixColumns();
      InvShiftRows();
      InvSubBytes();
    }
    // Add/XOR Round Key:
    XorData(expanded_keys, round*16);

    // XOR the 16 bytes of decrypted data with whatever is in cbc_buffer
    if (cbc_mode) XorData(cbc_buffer);
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
