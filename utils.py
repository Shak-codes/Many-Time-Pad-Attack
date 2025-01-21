import string


def load_words(file_path, previous_words=[]):
    """
    Reads a SCOWL word list from a text file and returns a set of words.
    Skips words that cannot be decoded in UTF-8.

    :param file_path: Path to the SCOWL word list file.
    :param previous_words: List of previously loaded word sets to avoid duplicates.
    :return: A set containing all words from the file.
    """
    words = set()
    with open(file_path, 'rb') as f:  # Open in binary mode to catch decoding errors
        for line_number, line in enumerate(f, 1):
            try:
                decoded_line = line.decode('utf-8').strip()  # Decode the line
                if decoded_line and not any(decoded_line in words_set for words_set in previous_words) and len(decoded_line) > 2:
                    words.add(decoded_line.lower())
            except UnicodeDecodeError:
                # print(f"Skipping invalid word on line {line_number}: {line}")
                continue  # Skip the problematic line
    return words


def read_ciphertexts(filename):
    """
    Reads lines from 'filename', each line is assumed to be hex-encoded or binary-encoded ciphertext.
    Returns a list of bytes objects, one per line.
    """
    ciphertexts = []

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # If it's a valid hex string, convert to bytes
            if is_hex_string(line):
                ciphertexts.append(bytes.fromhex(line))
            # Otherwise, treat as a binary string
            elif len(line) % 8 == 0 and all(c in '01' for c in line):
                byte_array = [int(line[i:i+8], 2)
                              for i in range(0, len(line), 8)]
                ciphertexts.append(bytes(byte_array))
            else:
                raise ValueError(f"Invalid line in file: {line}")

    return ciphertexts


def is_hex_string(s):
    """
    Checks if the given string represents a valid hexadecimal number.
    It allows an optional '0x' prefix, but this is not required.

    :param s: The string to check (e.g. "1A3F", "0x1A3F", or "FF").
    :return: True if s is a valid hex string, False otherwise.
    """
    # Optionally remove '0x' or '0X' prefix if present
    if s.lower().startswith("0x"):
        s = s[2:]

    # A valid hex string will have characters only in 0-9 and A-F/a-f
    hex_digits = string.hexdigits  # '0123456789abcdefABCDEF'
    return all(ch in hex_digits for ch in s)


def is_binary_string(s):
    """
    Checks if the given string represents a valid binary number.
    It allows an optional '0b' prefix, but this is not required.

    :param s: The string to check (e.g. "1010" or "0b110").
    :return: True if s is a valid binary string, False otherwise.
    """
    # Optionally remove '0b' or '0B' prefix if present
    if s.lower().startswith("0b"):
        s = s[2:]

    # Check if every character is '0' or '1'
    return all(ch in '01' for ch in s)


def is_printable_ascii(s):
    """
    Returns True if all characters in the input are printable ASCII
    and ensures that guessed substrings:
    - Do not have unsupported symbols or numbers at the start or end (except for ', . ').
    - Do not have random numbers or unsupported symbols between letters.
    """
    text = s.decode(
        'utf-8', errors='ignore')  # Decode bytes to string, ignoring errors
    punc = r'[!,.:;\'"?]'
    allowed_characters = string.ascii_letters + string.digits + punc + " "

    # Ensure all characters are printable ASCII
    if not all(c in allowed_characters for c in text):
        return False

    return True

# def generate_plaintext_slices(xor_slices, crib):
#     """
#     Generate plaintext slices using XOR slices and a known crib (part of plaintext).

#     Args:
#         xor_slices (list): A list of dictionaries containing:
#                            - "name": Name of the XOR pair (e.g., "x12").
#                            - "slice": A sliced XOR'd result as bytes.
#         crib (bytes): A known slice of plaintext (e.g., part of p1).

#     Returns:
#         dict: A dictionary mapping plaintext labels to the calculated slices.
#     """
#     plaintext_slices = {}

#     for xor_slice in xor_slices:
#         name = xor_slice["name"]
#         xor_result = xor_slice["slice"]
#         # Extract "p2", "p3", etc., from "x12", "x13", etc.
#         plaintext_label = f"p{name[1]}"
#         plaintext_slices[plaintext_label] = xor(xor_result, crib)

#     return plaintext_slices
