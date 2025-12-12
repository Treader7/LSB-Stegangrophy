### Steganography Exception classes ###
class SteganographyError(Exception):
    """Base class for steganography-related exceptions."""
    pass


class ImageFormatError(SteganographyError):
    """Raised when the image format is unsupported or unrecognized."""
    def __init__(self, format_found, message=""):
        self.format_found = format_found
        self.message = message or f"Unsupported image format: {format_found}"
        super().__init__(self.message)


class InsufficientCapacityError(SteganographyError):
    """Image too small for message"""
    def __init__(self, required, available):
        self.required = required
        self.available = available
        super().__init__(f"Need {required} bytes, have {available} bytes")


class CompressionDetectedError(SteganographyError):
    """Lossy compression detected"""
    pass


class ImageCorruptedError(SteganographyError):
    """Cannot parse image - it may be corrupted"""
    pass


class VerificationFailedError(SteganographyError):
    """Encoded data does not match original"""
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual
        super().__init__(f"Verification failed: checksum mismatch")

class EncodingError(SteganographyError):
     """ Raised when an error occurs during encoding """
     pass

class DecodingError(SteganographyError):
    """ Raised when an error occurs during decoding """
    pass

class MessageNotFoundError(SteganographyError):
    """ Raised when no hidden message is found in the image """
    pass

class ChecksumError(SteganographyError):
    """ Raised when there is a checksum mismatch """
    def __init__(self, expected, calculated):
        self.expected = expected
        self.calculated = calculated
        super().__init__(
            f"Message corrupted: checksum mismatch (expected {expected}, got {calculated})")

class MagicNumberError(SteganographyError):
    """ Raised when the magic number does not match """
    def __init__(self, found, expected):
        self.found = found
        self.expected = expected
        if found is None:
            message = "No hidden message found (magic number not detected)"
        else:
            message = f"Invalid magic number: found 0x{found:08X}, expected 0x{expected:08X}"
        super().__init__(message)
class InvalidMessageError(SteganographyError):
    """ Raised when the hidden message is invalid or malformed """
    pass

class MEssageTooLargeError(SteganographyError):
    """ Raised when the hidden message is too large for the image """
    def __init__(self, message_size, max_size):
        self.message_size = message_size
        self.max_size = max_size
        super().__init__(
            f"Message too large: {message_size} bytes exceeds maximum of {max_size} bytes")

class FileReadError(SteganographyError):
    """ Raised when there is an error reading a file """
    def __init__(self, filename, reason=""):
        self.filename = filename
        self.reason = reason
        message = f"Cannot read file '{filename}'"
        if reason:
            message += f": {reason}"
        super().__init__(message)

class FileWriteError(SteganographyError):
    """ Raised when there is an error writing to a file """
    def __init__(self, filename, reason=""):
        self.filename = filename
        self.reason = reason
        message = f"Cannot write file '{filename}'"
        if reason:
            message += f": {reason}"
        super().__init__(message)