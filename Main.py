### Main file ###
# Includes Encoding, decoding, scanning, and user interface.

from Constants import *
from Utils import *
from Errors import *
from BMP_Stego_Core import *

### Encoding ###
def encode_message(input_bmp, message, output_bmp):
    #Encodes a message into a bmp image
    print("Reading BMP file...")
    bmp_data = read_file_bytes(input_bmp) # read bmp fiel as bytes
    parser = BMPparser(bmp_data) # create parser to read bmp structure
    use_alpha = parser.has_alpha() # detect if rgb or rgba

    if use_alpha:
        print(f"Detected: {parser.bit_depth}-bit RGBA image")
        print(" Using alpha channel for encoding")
    else:
        print(f"Detected: {parser.bit_depth}-bit RGB image")
        print("Using RGB channels for encoding")
    print (f"Image size: {parser.width}x{parser.height}")
    capacity_bits=parser.get_capacity_bits(use_alpha)
    capacity_bytes=capacity_bits // 8
    print(f" Capacity: {capacity_bytes:,} bytes")
    binary_message= prepare_message_for_encoding(message)
    message_bits = len(binary_message)
    message_bytes = message_bits // 8
    print (f"Message length: {len(message)} characters")
    
    if message_bits > capacity_bits:
        raise InsufficientCapacityError(required=message_bytes, available=capacity_bytes)
    usage_precent = (message_bits / capacity_bits) * 100
    print("Capacity check passed")
    print(f"Using {usage_precent:.1f} % of available capacity")
    print("Encoding message into pixels")
    pixel_data =parser.get_pixel_data()
    encoded_pixels=encode_binary_in_pixels(pixel_data, binary_message, use_alpha=use_alpha)
    print("Message encoded successfully")
    print("\nReconstrcuting BMP")
    new_bmp_data=parser.reconstruct_bmp(encoded_pixels)
    write_file_bytes(output_bmp, new_bmp_data)
    output_size = len(new_bmp_data)
    print(f"Saved to: {output_bmp}")
    print(f"File size: {output_size:,} bytes")

    return{'success': True, 'output_file': output_bmp, "message_length": len(message), 'capacity_precent': usage_precent, 'format': 'RGBA' if use_alpha else 'RGB'}

def encode_from_file(input_bmp, message_file, output_bmp):
    # encode message from text file
    print(f"Reading message from: {message_file}")
    message= None
    try:
        with open(message_file, 'r', encoding='utf-8') as f:
            message=f.read()
    except FileNotFoundError:
        raise FileReadError(message_file, "Message file not found")
    except Exception as e:
        raise FileReadError(message_file, str(e))
    if not message:
        raise InvalidMessageError("Message file is empty")
    print(f"Read {len(message)} characters from file \n")
    return encode_message(input_bmp, message, output_bmp)

### Decoding ###
def decode_message(input_bmp):
    # Decode hidden message from bmp file
    print("Reading BMP file")
    if get_file_size(input_bmp) == 0:
        raise FileReadError(input_bmp, "File is empty or doesn't exist")
    bmp_data=read_file_bytes(input_bmp)
    parser=BMPparser(bmp_data)
    use_alpha=parser.has_alpha()
    if use_alpha:
        print(f"Detected: {parser.bit_depth}-bit RGBA image")
    else:
        print(f"Detected: {parser.bit_depth}-bit RGB image")
    pixel_data=parser.get_pixel_data()
    binary_data=decode_binary_from_pixels(pixel_data, use_alpha=use_alpha)
    try:
        message, is_valid, metadata =parse_encoded_message(binary_data)
    except MagicNumberError:
        print("Magic number not found")
        
        if use_alpha:
            binary_data =decode_binary_from_pixels(pixel_data, use_alpha=False)
            try:
                message, is_valid, metadata = parse_encoded_message(binary_data)
                use_alpha = False  
            except MagicNumberError:
                raise MagicNumberError(found=None, expected=Magic_number)
        else:
            raise MagicNumberError(found=None, expected=Magic_number)
    
    # Verify checksum
    if metadata['checksum_valid']:
        print("Checksum verified")
    else:
        print("Checksum verification failed")
    
    # Add extra info to metadata
    metadata['format'] = 'RGBA' if use_alpha else 'RGB'
    metadata['image_size'] = f"{parser.width}x{parser.height}"
    
    return message, metadata

def decode_to_file(input_bmp_path, output_file_path):
    #decode message and asave it to text file
    message_text, metadata = decode_message(input_bmp_path)
    print(f"\n Saving to: {output_file_path}")
    try:
        with open (output_file_path, 'w', encoding='utf-8') as f:
            f.write(message_text)
    except Exception as e:
        raise FileWriteError(output_file_path, str(e))
    return metadata

def scan_file(input_bmp):
    # scan BMP for hidden messages
    bmp_data = read_file_bytes(input_bmp)
    parser = BMPparser(bmp_data)
    pixel_data = parser.get_pixel_data()
    detected_with_alpha = False
    if parser.has_alpha():
        print("  Checking with alpha channel...")
        binary_with_alpha = decode_binary_from_pixels(pixel_data, use_alpha=True)
        # Just check first 32 bits for magic number
        if len(binary_with_alpha) >= 32:
            magic = binary_to_int(binary_with_alpha[0:32])
            detected_with_alpha = (magic == Magic_number)
    binary_without_alpha = decode_binary_from_pixels(pixel_data, use_alpha=False)
    detected_without_alpha = False
    if len(binary_without_alpha) >= 32:
        magic = binary_to_int(binary_without_alpha[0:32])
        detected_without_alpha = (magic == Magic_number)
    detected = detected_with_alpha or detected_without_alpha
    if detected:
        if detected_with_alpha:
            method = "RGBA"
        else:
            method = "RGB"
        
        suspicion = "HIGH - Hidden message detected"
        recommendation = "Use decode function to extract the message"
    else:
        method = "None"
        suspicion = "NONE - No hidden message detected"
        recommendation = "Image appears to be clean"
    
    return {
        'detected': detected,
        'detected_with_alpha': detected_with_alpha,
        'detected_without_alpha': detected_without_alpha,
        'method': method,
        'suspicion': suspicion,
        'recommendation': recommendation,
        'width': parser.width,
        'height': parser.height,
        'bit_depth': parser.bit_depth
    }

### User Interface ###
def print_menu():
    #Display main menu options
    print("\n" + "=" * 60)
    print("MAIN MENU")
    print("=" * 60)
    print("1. Encode message (type message)")
    print("2. Encode message (read from file)")
    print("3. Decode message (display on screen)")
    print("4. Decode message (save to file)")
    print("5. Scan BMP for hidden data")
    print("6. Exit")
    print("=" * 60)

def handle_encode_text():
    #Handle Option 1: Type message directly
    print("\n" + "=" * 60)
    print("ENCODE MESSAGE (TYPE MESSAGE)")
    print("=" * 60)
    
    # Get file paths from user
    input_bmp_file = input("\nInput BMP file: ").strip()
    output_bmp_file = input("Output BMP file: ").strip()
    
    # Get message from user
    print("\nEnter your message:")
    print("(Type your message. Press Enter on empty line when done)")
    print("-" * 60)
    
    message_lines = []
    while True:
        try:
            line = input()
            # Empty line after = done
            if not line and message_lines:
                break
            message_lines.append(line)
        except EOFError:
            break
    user_message = '\n'.join(message_lines)
    
    # Check if user actually typed something
    if not user_message.strip():
        print("\nNo message entered!")
        return
    
    print("-" * 60)
    
    # Encode it
    try:
        print()
        result = encode_message(input_bmp_file, user_message, output_bmp_file)
        print("\n" + "=" * 60)
        print("ENCODING SUCCESSFUL")
        print("=" * 60)
        print(f"Output: {result['output_file']}")
        print(f"Message: {result['message_length']} characters")
        print(f"Format: {result['format']}")
        print(f"Capacity used: {result['capacity_percent']:.1f}%")
        print("=" * 60)
        
    except SteganographyError as e:
        print(f"\nEncoding failed: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

def handle_encode_file():
    # Handle Option 2: Read message from file
    print("\n" + "=" * 60)
    print("ENCODE MESSAGE (FROM FILE)")
    print("=" * 60)
    
    # Get file paths from user
    input_bmp_file = input("\nInput BMP file: ").strip()
    message_txt_file = input("Message text file: ").strip()
    output_bmp_file = input("Output BMP file: ").strip()
    
    # Encode from file
    try:
        print()
        result = encode_from_file(input_bmp_file, message_txt_file, output_bmp_file)
        print("\n" + "=" * 60)
        print("ENCODING SUCCESSFUL")
        print("=" * 60)
        print(f"Output: {result['output_file']}")
        print(f"Message: {result['message_length']} characters")
        print(f"Format: {result['format']}")
        print(f"Capacity used: {result['capacity_percent']:.1f}%")
        print("=" * 60)
        
    except SteganographyError as e:
        print(f"\nEncoding failed: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

def handle_decode_display():
    #Handle Option 3: Decode and show on screen
    print("\n" + "=" * 60)
    print("DECODE MESSAGE (DISPLAY)")
    print("=" * 60)
    
    # Get file path from user
    input_bmp_file = input("\nInput BMP file: ").strip()
    
    # Decode
    try:
        print()
        decoded_message, metadata = decode_message(input_bmp_file)
        
        # Display message
        print("\n" + "=" * 60)
        print("DECODING SUCCESSFUL")
        print("=" * 60)
        print(f"Format: {metadata['format']}")
        print(f"Message length: {metadata['message_length_chars']} characters")
        print(f"Checksum: {'Valid' if metadata['checksum_valid'] else 'Invalid'}")
        print("=" * 60)
        print("\nDECODED MESSAGE:")
        print("-" * 60)
        print(decoded_message)
        print("-" * 60)
        
    except SteganographyError as e:
        print(f"\nDecoding failed: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")


def handle_decode_to_file():
    #Handle Option 4: Decode and save to file
    print("\n" + "=" * 60)
    print("DECODE MESSAGE (SAVE TO FILE)")
    print("=" * 60)
    
    # Get file paths from user
    input_bmp_file = input("\nInput BMP file: ").strip()
    output_txt_file = input("Output text file: ").strip()
    
    # Decode and save
    try:
        print()
        metadata = decode_to_file(input_bmp_file, output_txt_file)
        
        # Show success
        print("\n" + "=" * 60)
        print("DECODING SUCCESSFUL")
        print("=" * 60)
        print(f"Output file: {output_txt_file}")
        print(f"Message length: {metadata['message_length_chars']} characters")
        print(f"Checksum: {'Valid' if metadata['checksum_valid'] else 'Invalid'}")
        print("=" * 60)
        
    except SteganographyError as e:
        print(f"\nDecoding failed: {e}")
    except Exception as e:
        print(f"\nUnexpected error: {e}")


def handle_scan():
    #Handle Option 5: Scan for hidden data
    print("\n" + "=" * 60)
    print("SCAN BMP FOR HIDDEN DATA")
    print("=" * 60)
    
    input_bmp_file = input("\nInput BMP file: ").strip()
    
    try:
        print()
        scan_results = scan_file(input_bmp_file)
        
        # Display scan results
        print("\n" + "=" * 60)
        print("SCAN RESULTS")
        print("=" * 60)
        print(f"Image: {scan_results['width']}×{scan_results['height']} {scan_results['bit_depth']}-bit")
        print("\nDetection Results:")
        print("-" * 60)
        
        if scan_results['detected']:
            print(f"Status: HIDDEN MESSAGE DETECTED")
            print(f"Method: {scan_results['method']}")
        else:
            print(f"Status: No hidden message detected")
        
        print(f"\nSuspicion: {scan_results['suspicion']}")
        print(f"Recommendation: {scan_results['recommendation']}")
        print("=" * 60)
        
    except Exception as e:
        print(f"\nScan failed: {e}")


def main():
    # Main application
    
    while True:
        print_menu()
        user_choice = input("\nEnter choice (1-6): ").strip()
        
        # Route to appropriate handler
        if user_choice == '1':
            handle_encode_text()
        elif user_choice == '2':
            handle_encode_file()
        elif user_choice == '3':
            handle_decode_display()
        elif user_choice == '4':
            handle_decode_to_file()
        elif user_choice == '5':
            handle_scan()
        elif user_choice == '6':
            print("\nThank you for using BMP Steganography Tool!")
            print("=" * 60)
            break  # Exit loop
        else:
            print("\nInvalid choice. Please enter 1-6.")
        
        # Pause before showing menu again
        input("\nPress Enter to continue...")

### Run ###
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user. Exiting")
    except Exception as e:
        print("Error")