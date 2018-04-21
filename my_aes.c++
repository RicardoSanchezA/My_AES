#include "my_aes.h"
#include "lookup_tables.h"

// Error message
const char* key_error_message = "Error: the key file provided is not large \
to contain a key of the specified size.";
const char* file_error_message = "Error: At least one of the files provided \
is invalid.";

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
    Error(file_error_message);
  }
  // Set CBC mode flag
  cbc_mode = _cbc_mode;
  // Initialize vector where we'll store expanded keys
  expanded_keys = std::vector<byte>(key_size == 128 ? 176 : 240);
  // Initialize data structures used for CBC mode
  if (cbc_mode) {
    cbc_buffer = std::vector<byte>(DATA_SIZE);
  }
}

// Private/Helper Methods
void MyAES::CheckPadding() {
  int8_t row, col;
  row = col = DATA_DIMENSION-1;
  pad_size = 0;
  while (col >= 0 && data[row][col] == 0) {
    --row;
    if (row < 0) {
      row = DATA_DIMENSION-1;
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
  for (i = 0; i < DATA_SIZE && key_file.get(c); ++i) {
    cbc_buffer[i] = c;
  }
  // Verify we read full 16 bytes of data from key file
  if (i != DATA_SIZE) Error(key_error_message);
}
void MyAES::LoadData() {
  char c;
  uint8_t row, col;
  row = col = data_size = 0;
  // Read data from input file (one char/byte at a time)
  while (data_size < DATA_SIZE && in_file.get(c)) {
    data[row][col] = c;
    ++row;
    if (row > DATA_DIMENSION-1) {
      row = 0;
      ++col;
    }
    ++data_size;
  }
  if (data_size > 0) {
    // If the data matrix is partially full, then
    // fill in the remaining spots with zeros.
    while (data_size < DATA_SIZE) {
      data[row][col] = 0;
      ++row;
      if (row > DATA_DIMENSION-1) {
        row = 0;
        ++col;
      }
      ++data_size;
    }
  }
}
void MyAES::SubBytes(const uint8_t* table) {
  for (uint8_t i = 0; i < DATA_DIMENSION; ++i) {
    for (uint8_t j = 0; j < DATA_DIMENSION; ++j) {
      data[i][j] = table[data[i][j]];
    }
  }
}
void MyAES::ShiftLeft(byte* row) {
  byte temp = row[0];
  for (uint8_t i = 0; i < DATA_DIMENSION-1; ++i)
    row[i] = row[i + 1];
  row[DATA_DIMENSION-1] = temp;
}
void MyAES::ShiftRows() {
  for (uint8_t i = 1; i <= DATA_DIMENSION-1; ++i) {
    for (uint8_t j = 1; j <= i; ++j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::InvShiftRows() {
  for (uint8_t i = 1; i <= DATA_DIMENSION-1; ++i) {
    for (uint8_t j = DATA_DIMENSION-1; j >= i; --j) {
      ShiftLeft(data[i]);
    }
  }
}
void MyAES::MixColumns(const uint8_t (&matrix)[DATA_DIMENSION][DATA_DIMENSION]){
  byte temp[DATA_DIMENSION][DATA_DIMENSION] = {{0,0,0,0},{0,0,0,0},
                                               {0,0,0,0},{0,0,0,0}};
  // We will use 'temp' to store the result of the matrix multiplication
  // between 'data' and 'matrix'. 'matrix' will either be 'galois_matrix'
  // or 'inv_galois_matrix' depending on whether we're doing MixColumns  
  // or InvMixColumns.
  for (uint8_t i = 0; i < DATA_DIMENSION; ++i) {
    for (uint8_t j = 0; j < DATA_DIMENSION; ++j) {
      for (uint8_t k = 0; k < DATA_DIMENSION; ++k) {
        uint8_t a = matrix[j][k];
        byte b = data[k][i];
        switch(a) {
          case 1: temp[j][i] ^= b;
            break;
          case 2: temp[j][i] ^= two[b];
            break;
          case 3: temp[j][i] ^= three[b];
            break;
          case 9: temp[j][i] ^= nine[b];
            break;
          case 11: temp[j][i] ^= eleven[b];
            break;
          case 13: temp[j][i] ^= thirteen[b];
            break;
          case 14: temp[j][i] ^= fourteen[b];
            break;
          default: Error("Error: Galois matrix is corrupt.");
            break;
        }
      }
    }
  }
  // Store the result of the matrix multiplication in 'data'
  for (uint8_t i = 0; i < DATA_DIMENSION; ++i) {
    for (uint8_t j = 0; j < DATA_DIMENSION; ++j) {
      data[i][j] = temp[i][j];
    }
  }
}
void MyAES::GenerateKeyCore(byte in[], const uint8_t& i) {
  // Shift bytes to the left (rotate)
  ShiftLeft(in);
  // Apply S-table on all bytes
  for (uint8_t a = 0; a < DATA_DIMENSION; ++a) {
    in[a] = s[in[a]];
  }
  // XOR leftmost byte with RCON-table
  in[0] ^= rcon[i];
}
void MyAES::StoreData() {
  // Check if there is any padding that we should omit
  CheckPadding();
  // Write contents of 'data' into our output file
  for (uint8_t i = 0, k = 0; i < DATA_DIMENSION; ++i) {
    for (uint8_t j = 0; j < DATA_DIMENSION; ++j, ++k) {
      if (k < data_size - pad_size) out_file << data[j][i];
    }
  }
}
void MyAES::CopyData(std::vector<byte>& v) {
  // Copy all of the data stored in 'data' into 'v'
  for (uint8_t i = 0, k = 0; i < DATA_DIMENSION; ++i) { 
    for (uint8_t j = 0; j < DATA_DIMENSION; ++j, ++k) {
      v[k] = data[j][i];
    }
  }
}
void MyAES::XorData(const std::vector<byte>& v, const uint8_t& offset) {
  // XOR the contents of 'data' with the first 16 items/bytes of 'v' starting
  // at 'offset'. The first byte of 'data' will be XORed with the first byte
  // of 'v' (taking into account 'offset'), the second byte of 'data' will be
  // XORed with the second byte of 'v', and so on until we have XORed all 16
  // bytes of 'data'.
  for (uint8_t i = 0, k = 0; i < DATA_DIMENSION; ++i) { 
    for (uint8_t j = 0; j < DATA_DIMENSION; ++j, ++k) {
      data[j][i] ^= v[k + offset];
    }
  }
}
void MyAES::Error(const char* msg) {
  // Something went wrong... :(
  fprintf(stderr, "%s\n", msg);
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
    if (i != n) Error(key_error_message);
  }
  // Generate expanded keys using the specified iterative process
  for (uint16_t processed_bytes = n, num_key = 1; 
       processed_bytes < expanded_keys.size(); processed_bytes += 4) {
    // Assign the value of the previous 4 bytes to 'temp'. We are
    // going to build the next 4 bytes of our expanded key in 'temp'.
    for (uint8_t i = 0; i < 4; ++i) {
      temp[i] = expanded_keys[processed_bytes + i - 4];
    }
    // Every 'n' bytes (size of each key) we want to re-
    // generate the core part of the next expanded key.
    if (processed_bytes % n == 0) {
      GenerateKeyCore(temp, num_key);
      ++num_key;
    }
    // For 256-bit keys, we need to make a substitution using S-lookup-table
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
  uint8_t total_rounds = (key_size == 128) ? 10 : 14;
  while (1) {
    // Get next 16 bytes of data from input file
    LoadData();
    // Stop if no data was extracted (i.e. EOF)
    if (data_size == 0) break;
    // XOR the 16 bytes of data with whatever is in 'cbc_buffer'
    // 'cbc_buffer' initially holds the initialization vector.
    if (cbc_mode) XorData(cbc_buffer);
    
    // Do iterative process to encrypt data:
    uint8_t num_round = 0;
    // Add/XOR Round Key:
    XorData(expanded_keys, num_round*EXPANDED_KEY_SIZE);
    for (++num_round; num_round < total_rounds; ++num_round) {
      SubBytes(s);
      ShiftRows();
      MixColumns(galois_matrix);
      //Add/XOR Round Key:
      XorData(expanded_keys, num_round*EXPANDED_KEY_SIZE);
    }
    SubBytes(s);
    ShiftRows();
    // Add/XOR Round Key:
    XorData(expanded_keys, num_round*EXPANDED_KEY_SIZE);

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
    uint8_t num_round = (key_size == 128) ? 10 : 14;
    // Get next 16 bytes of data from input file
    LoadData();
    // Stop if no data was extracted (i.e. EOF)
    if (data_size == 0) break;
    // Copy the 16 bytes of data into 'temp'
    if (cbc_mode) CopyData(temp);

    // Do the inverse of the iterative process to decrypt:
    // Add/XOR Round Key:
    XorData(expanded_keys, (num_round)*EXPANDED_KEY_SIZE);
    InvShiftRows();
    SubBytes(inv_s);
    for (--num_round; num_round > 0; --num_round) {
      // Add/XOR Round Key:
      XorData(expanded_keys, num_round*EXPANDED_KEY_SIZE);
      MixColumns(inv_galois_matrix);
      InvShiftRows();
      SubBytes(inv_s);
    }
    // Add/XOR Round Key:
    XorData(expanded_keys, num_round*EXPANDED_KEY_SIZE);

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
