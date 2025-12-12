BMP_signature= b'BM' # BMP files start signature (first 2 bytes of the file)
Magic_number=0xAAFF7799 # unique identfier or signature
Supported_Bit_Depths= [24, 32] # supported bit depths for BMP files 24 for RBG and 32 for RGBA
Max_Message_Size= 1000000  # 1 MB
BMP_header_size= 54 # BMP header size so we can tell where pixel data starts
Header_size_bits = 96 # size of steganography header in bits
Supported_Extensions= ['.bmp'] # Supported file extensions
Default_Output_Extension= ['.bmp'] # default output file extension