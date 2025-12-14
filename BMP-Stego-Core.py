### bmp-stego-core ###
# BMP file parser: reads bmp images and pixel/header data
# LSB bit manipulation embedding or extracting bitss
# Message encoding/decoding for header and checksum

from Constants import *
from Utils import *
from Errors import *

### BMP file parser
class BMPparser:
    ## parses BMP image file extracting pixel data
    
    def __init__(self, file_bytes):
        # intialize parser with bmp's file bytes
        self.file_bytes = file_bytes # store file
        self.width=0 # Image width in pixels
        self.height=0 # Image height in pixels
        self.bit_depth=0 # bits per pixel 24,32
        self.channels=0 # number of color channels 3 for rgb and 4 for rgba
        self.pixel_data_offset=0 # where the pixel data starts after header
        self.row_padding= 0 # padding bytes per row
        self.pixel_data= None # pixel data without padding
        self.parse() # parse bmp file

    def parse(self):
        # parse bmp file and extarct header info 
        # structure is as so bytes 0-1: signature, 10-13: pixel data offset, 18-21: width, 22-25: height, 26-27: color planes, 28-29: bits per pixel, 30-33: compression
        if len(self.file_bytes)<54:
            raise ImageCorruptedError ("File too small to be a bmp file ")
        # checks the bmp siganture first 2 bytes must be BM in header
        if self.file_bytes[:2] != BMP_signature:
            raise ImageCorruptedError ("Invalid BMP siganture")
        #read pixel data offset 
        self.pixel_data_offset = bytes_to_int(self.file_bytes, 10, 4, 'little')
        # read image dimensions
        self.width = bytes_to_int(self.file_bytes, 18, 4, 'little')
        self.height = bytes_to_int(self.file_bytes, 22, 4, 'little')
        # read color planes muse be 1 for bmp format
        planes = bytes_to_int(self.file_bytes, 26, 2, 'little')
        if planes != 1:
            raise ImageCorruptedError("Invalid BMP: color planes = {planes} (must be 1)")
        # read bits per pixel or channels either 24:rgb or 32:rgba
        self.bit_depth = bytes_to_int(self.file_bytes, 28, 2, 'little')
        
        # Check if it's a supported bit depth
        if self.bit_depth not in Supported_Bit_Depths:
            raise ImageFormatError("{self.bit_depth}-bit", "Only 24-bit and 32-bit BMPs supported")
        
        # Read compression type must be 0 for uncompressed
        compression = bytes_to_int(self.file_bytes, 30, 4, 'little')
        if compression != 0:
            raise CompressionDetectedError("Only uncompressed BMPs supported")
        
        # Determine number of channels based on bit depth
        # 24-bit = 3 channels rgb
        # 32-bit = 4 channels rgba
        self.channels = 3 if self.bit_depth == 24 else 4
        
        # Calculate row padding BMP rows must be multiples of 4 bytes
        self._calculate_row_padding()

    def calaculate_row_padding(self):
        # calclate padding bytes that are added to rows as bmp needs each row to be 4 bytes 
        bytes_per_pixel = self.channels # 3 for rgb and 4 for rgba
        row_size= self.width * bytes_per_pixel # data per row
        self.row_padding= (4-(row_size % 4)) % 4 # padding if needed
    
    def get_pixel_data(self):
        # extarct pixel data from bmp file
        # if extarcted return
        if self.pixel_data is not None:
            return self.pixel_data
        bytes_per_pixel =self.channels 
        # row size with padding
        row_size_with_padding=self.width * bytes_per_pixel + self.row_padding
        pixel_data = bytearray() # store data without padding
        # extarct pixels 
        for y in range(self.height):
            row_index=self.height -1 -y
            row_offset = self.pixel_data_offset + row_index * row_size_with_padding
            for x in range(self.width):
                pixel_offset=row_offset+x*bytes_per_pixel
                for c in range(self.channels):
                    byte_pos=pixel_offset+c
                    if byte_pos<len(self.file_bytes):
                        pixel_data.append(self.file_bytes[byte_pos])
                    else:
                        pixel_data.append
        self.pixel_data=bytes(pixel_data)
        return self.pixel_data
    
    def has_alpha(self):
        # check if image has alpha channel
        return self.bit_depth ==32
    
    def get_capacity_bits(self, use_alpha=True):
        #calculate how many bits we can hide in this image
        # capacity is pixels times number of channels minus the header
        if self.bit_depth ==24:
            usable_channels =3 # rgb
        elif self.bit_depth ==32:
            usable_channels = 4 if use_alpha else 3 
        else:
            return 0
        total_pixels=self.width *self.height
        available_bits=total_pixels *usable_channels
        available_bits-=Header_size_bits
        return max(0, available_bits)
    
    def reconstruct_bmp(self, modified_pixel_data):
        # reconstruct bmp file with modified pixels
        header= self.file_bytes[:self.pixel_data_offset]
        bytes_per_pixel= self.channels
        row_size_with_padding=self.width * bytes_per_pixel + self.row_padding
        new_pixel_data= bytearray()
        src_index=0

        for y in range(self.height):
            row_data = bytearray()
            for x in range(self.width):
                for c in range(self.channels):
                    if src_index < len(modified_pixel_data):
                        row_data.append(modified_pixel_data[src_index])
                        src_index+=1
                    else:
                        row_data.append
            for _ in range(self.row_padding):
                row_data.append(0)
            new_pixel_data.extend(row_data)
        rows=[]
        for i in range (0, len (new_pixel_data), row_size_with_padding):
            rows.append(new_pixel_data[i:i + row_size_with_padding])
        rows.reverse()  
        
        
        new_pixel_data = bytearray()
        for row in rows:
            new_pixel_data.extend(row)
        
        # Combine header + pixel data
        reconstructed = header + bytes(new_pixel_data)
        
        # Update file size in header 
        file_size_bytes = int_to_bytes(len(reconstructed), 4, 'little')
        reconstructed = reconstructed[:2] + file_size_bytes + reconstructed[6:]
        
        return bytes(reconstructed)
    

    ### LSB Bit manipulation ###
def embed_bit_in_byte(byte_value, bit):
    # embed single bit into lsb
    
    bit_int = 1 if (bit == '1' or bit == 1) else 0
    return (byte_value & 0xFE) | bit_int


def extract_bit_from_byte(byte_value):
    # extarct lsb from a byte
    return '1' if (byte_value & 0x01) else '0'
    
    ### Message preperation ###
def prepare_message_for_encoding(message):
    # prepare message for encoding header and checksum
    # Validate message
    if not message or not isinstance(message, str):
        raise InvalidMessageError("Message must be a non-empty string")
    
    if len(message) > Max_Message_Size:
        raise MessageTooLargeError(len(message), Max_Message_Size)
    
    # Convert message to binary 
    message_binary = string_to_binary(message)
    message_length = len(message_binary)
    
    # Calculate checksum 
    checksum = calculate_checksum(message)
    
    # Create header components 
    magic_binary = int_to_binary(Magic_number, 32)      # Our signature
    length_binary = int_to_binary(message_length, 32)   # Message length in bits
    checksum_binary = int_to_binary(checksum, 32)       # Integrity check
    
    # Combine
    complete_binary = magic_binary + length_binary + checksum_binary + message_binary
    
    return complete_binary
def parse_encoded_message(binary_data):
    # parse binary data to extarct hidden data if any exist
    if len(binary_data) < Header_size_bits:
        raise MagicNumberError(found=None, expected=Magic_number)
    
    # Extract header fields 
    magic_binary = binary_data[0:32]
    length_binary = binary_data[32:64]    
    checksum_binary = binary_data[64:96]  
    
    # Convert binary strings to integers
    magic = binary_to_int(magic_binary)
    message_length = binary_to_int(length_binary)
    expected_checksum = binary_to_int(checksum_binary)
    
    # Verify magic number 
    if magic != Magic_number:
        raise MagicNumberError(found=magic, expected=Magic_number)
    
    # Check if we have enough data for the full message
    total_bits_needed = Header_size_bits + message_length
    if len(binary_data) < total_bits_needed:
        raise ValueError("Incomplete message: need {total_bits_needed} bits")
    
    # Extract message binary start after header
    message_binary = binary_data[Header_size_bits:Header_size_bits + message_length]
    
    # Convert binary back to text
    try:
        message_text = binary_to_string(message_binary)
    except Exception as e:
        raise DecodingError("Failed to convert binary to text: {str(e)}")
    
    # Verify checksum
    calculated_checksum = calculate_checksum(message_text)
    is_valid = (calculated_checksum == expected_checksum)
    
    if not is_valid:
        raise ChecksumError(expected=expected_checksum, calculated=calculated_checksum)
    
    # Prepare metadata to return 
    metadata = {
        'message_length_chars': len(message_text),
        'message_length_bits': message_length,
        'checksum_valid': is_valid,
        'magic_number': magic,
        'total_bits': total_bits_needed
    }
    
    return message_text, is_valid, metadata

### LSB encoding/decoding ###
def encode_binary_in_pixels(pixel_data, binary_message, use_alpha=True):
    # encode binary message into pixel lsb
    if len(pixel_data) == 0:
        raise ValueError("Pixel data is empty")
    
    # Determine format based on data length
    if len(pixel_data) % 4 == 0 and use_alpha:
        bytes_per_pixel = 4
        channels_per_pixel = 4
    else:
        bytes_per_pixel = 3
        channels_per_pixel = 3
    
    # Convert to bytearray so we can modify it
    pixels = bytearray(pixel_data)
    message_length = len(binary_message)
    message_index = 0 
    
    # Sequential encoding: go through pixels one by one
    for i in range(0, len(pixels), bytes_per_pixel):
        # Stop if we've encoded entire message
        if message_index >= message_length:
            break
        
        # Encode bits in each channel of this pixel
        for channel in range(min(channels_per_pixel, bytes_per_pixel)):
            if message_index >= message_length:
                break
            
            # Get next bit from message
            bit = binary_message[message_index]
            pixel_index = i + channel
            
            # Embed bit in this byte's LSB
            if pixel_index < len(pixels):
                pixels[pixel_index] = embed_bit_in_byte(pixels[pixel_index], bit)
                message_index += 1
    
    return bytes(pixels)

def decode_binary_from_pixels(pixel_data, use_alpha=True, max_bits=None):
    # decode binary message from pixel LSB
    if len(pixel_data) == 0:
        return ""
    
    # Determine format
    if len(pixel_data) % 4 == 0 and use_alpha:
        bytes_per_pixel = 4
        channels_per_pixel = 4
    else:
        bytes_per_pixel = 3
        channels_per_pixel = 3
    
    binary_message = ""
    
    if max_bits is None:
        # Extract all bits
        for i in range(0, len(pixel_data), bytes_per_pixel):
            for channel in range(min(channels_per_pixel, len(pixel_data) - i)):
                binary_message += extract_bit_from_byte(pixel_data[i + channel])
    else:
        # Extract up to max_bits
        bits_extracted = 0
        for i in range(0, len(pixel_data), bytes_per_pixel):
            for channel in range(min(channels_per_pixel, len(pixel_data) - i)):
                if bits_extracted >= max_bits:
                    break
                binary_message += extract_bit_from_byte(pixel_data[i + channel])
                bits_extracted += 1
            if bits_extracted >= max_bits:
                break
    
    return binary_message