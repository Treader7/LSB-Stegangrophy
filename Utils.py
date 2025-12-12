### Utiltiy functions for File I/O, Data conversions, and Checksums ###

from Constants import *
from Errors import *


### FILE I/O OPERATIONS ###

def read_file_bytes(filename):
  
    # Read entire file as bytes
   
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        raise FileReadError(filename, "File not found")
    except PermissionError:
        raise FileReadError(filename, "Permission denied")
    except Exception as e:
        raise FileReadError(filename, str(e))


def write_file_bytes(filename, data):
    
    # Write bytes to file
    
    try:
        with open(filename, 'wb') as f:
            f.write(data)
        return True
    except PermissionError:
        raise FileWriteError(filename, "Permission denied")
    except Exception as e:
        raise FileWriteError(filename, str(e))


def get_file_size(filename):
    
    # Get file size in bytes.
    
    try:
        with open(filename, 'rb') as f:
            f.seek(0, 2)
            return f.tell()
    except:
        return 0


### Byte/Integer Conversions ###

def bytes_to_int(byte_array, start, length, endian='little'):

    # Convert bytes to integer.
  
    if start + length > len(byte_array):
        raise ValueError("Requested bytes beyond array length")
    
    # Extract the slice of bytes
    byte_slice = byte_array[start:start + length]
    
    # Convert using Python's built-in method
    return int.from_bytes(byte_slice, endian)


def int_to_bytes(value, length, endian='little'):

    # Convert integer to bytes.
   
    if value < 0:
        raise ValueError("Cannot convert negative integer to bytes")
    
    max_value = (1 << (length * 8)) - 1
    if value > max_value:
        raise ValueError(f"Value {value} too large for {length} bytes")
    
    # Convert using Python's built-in method
    return value.to_bytes(length, endian)


### TEXT/BINARY STRING CONVERSIONS ###

def string_to_binary(text):
 
    # Convert text string to binary string representation.
    
    if not isinstance(text, str):
        raise TypeError("Input must be a string")
    
    if not text:
        return ""
    
    # Encode to UTF-8 bytes
    text_bytes = text.encode('utf-8')
    
    # Convert each byte to 8-bit binary string
    binary_str = ''
    for byte in text_bytes:
        binary_str += format(byte, '08b')
    
    return binary_str


def binary_to_string(binary_str):
  
    # Convert binary string back to text.

    if not isinstance(binary_str, str):
        raise TypeError("Input must be a string")
    
    if not binary_str:
        return ""
    
    # Trim to multiple of 8 bits
    if len(binary_str) % 8 != 0:
        binary_str = binary_str[:-(len(binary_str) % 8)]
    
    if not binary_str:
        return ""
    
    # Convert each 8-bit chunk to a byte
    bytes_list = []
    for i in range(0, len(binary_str), 8):
        chunk = binary_str[i:i + 8]
        if len(chunk) != 8:
            break
        
        byte_value = int(chunk, 2)
        bytes_list.append(byte_value)
    
    # Convert bytes to string
    text_bytes = bytes(bytes_list)
    
    try:
        # Try UTF-8 decoding first
        return text_bytes.decode('utf-8')
    except UnicodeDecodeError:
        # Fall back to latin-1 if UTF-8 fails
        return text_bytes.decode('latin-1', errors='ignore')


def int_to_binary(value, bit_length=32):
  
    # Convert integer to binary string of fixed length.
   
    if value < 0:
        raise ValueError("Cannot convert negative integer to binary")
    
    max_value = (1 << bit_length) - 1
    if value > max_value:
        raise ValueError(f"Value {value} too large for {bit_length} bits")
    
    # Convert to binary and remove '0b' prefix
    binary = bin(value)[2:]
    
    # Pad with zeros to desired length
    return binary.zfill(bit_length)


def binary_to_int(binary_str):
    
    # Convert binary string to integer.
  
    if not binary_str:
        return 0
    
    # Validate that string contains only 0s and 1s
    for char in binary_str:
        if char not in '01':
            raise ValueError(f"Invalid binary character: '{char}'")
    
    return int(binary_str, 2)


### CHECKSUM FUNCTIONS (DATA INTEGRITY) ###

def calculate_checksum(data):
    
    # Calculate simple checksum for data integrity verification.
   
    if isinstance(data, str):
        data = data.encode('utf-8')
    elif not isinstance(data, (bytes, bytearray)):
        raise TypeError("Data must be string or bytes")
    
    checksum = 0
    
    # Sum all bytes with 32-bit overflow wrap
    for byte in data:
        checksum = (checksum + byte) & 0xFFFFFFFF
    
    return checksum


def verify_checksum(data, expected_checksum):
    
    # Verify data checksum.
    
    calculated = calculate_checksum(data)
    return calculated == expected_checksum


### VALIDATION FUNCTIONS ###

def validate_bmp_format(bmp_data):
    
    # Quick validation of BMP file format.
    
    # Check minimum size
    if len(bmp_data) < 54:
        return False, "File too small to be a valid BMP"
    
    # Check signature
    if bmp_data[0:2] != BMP_signature:
        return False, "Not a BMP file (invalid signature)"
    
    # Check bit depth
    try:
        bit_depth = bytes_to_int(bmp_data, 28, 2, 'little')
        if bit_depth not in Supported_Bit_Depths:
            return False, f"Unsupported bit depth: {bit_depth}"
    except:
        return False, "Cannot read bit depth"
    
    return True, "Valid BMP format"


def validate_message_length(message, max_size=Max_Message_Size):
    
    # Validate message length is within limits.
    
    if not message:
        return False, "Message is empty"
    
    if len(message) > max_size:
        return False, f"Message too long: {len(message)} chars, max {max_size}"
    
    return True, "Message length valid" 