import string
from itertools import islice


def split_set(s, n):
    """ Splits a set into `n` roughly equal contiguous parts. """
    s = list(s)  # Convert set to list to maintain order
    chunk_size = len(s) // n
    remainder = len(s) % n  # Some chunks may need an extra word

    chunks = []
    start = 0
    for i in range(n):
        end = start + chunk_size + (1 if i < remainder else 0)
        chunks.append(set(s[start:end]))
        start = end

    return chunks


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
    try:
        text = s.decode(
            'utf-8')  # Decode bytes to string, ignoring errors
    except:
        return False
    punc = r'[!,.:;\'"?]'
    allowed_characters = string.ascii_letters + punc + " "

    # Ensure all characters are printable ASCII
    if not all(c in allowed_characters for c in text):
        return False

    return True


def valid_string(send_command, slice, word, dict):
    is_word = word in dict
    if not is_printable_ascii(word) or len(send_command(
            "search", word.decode("utf-8"))) == 0:
        return False
    idx = slice.find(word)
    if slice[idx-1] == " " and\
            slice[idx + len(word) - 1] == " " and\
            not is_word:
        return False
    return True
