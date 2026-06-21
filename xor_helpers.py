from utils import is_printable_ascii, valid_string, valid_res
import subprocess
import json
import os

# Start the C++ process. Resolve to an absolute path: Windows CreateProcess does
# not search the current working directory for a bare filename, so passing just
# "WordTrie.exe" fails unless it happens to be on PATH.
WORDTRIE_EXE = os.path.abspath("WordTrie.exe")
process = subprocess.Popen(
    WORDTRIE_EXE,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Read and discard the startup message
startup_message = process.stdout.readline().strip()
print(f"Startup Message: {startup_message}")


# Memoize responses: crib-dragging issues the same prefix/suffix queries over
# and over, and each one is a subprocess round-trip.
_command_cache = {}


def send_command(command, type_, string):
    """
    Send a command to the C++ process and return the parsed JSON response.

    Args:
        command (str): "search" or "count"
        type_ (str): "prefix" or "suffix"
        string (str): the input string to search/count

    Returns:
        dict or list: JSON-decoded result from the C++ program
    """
    key = (command, type_, string)
    cached = _command_cache.get(key)
    if cached is not None:
        return cached

    # Construct and send JSON input
    input_data = json.dumps({
        "command": command,
        "type": type_,
        "string": string
    })
    process.stdin.write(input_data + "\n")
    process.stdin.flush()

    # Read and decode response
    response = process.stdout.readline()
    result = json.loads(response)
    _command_cache[key] = result
    return result


def xor(bytes_seq1, bytes_seq2):
    """
    XOR two byte sequences of equal length.

    Args:
        bytes_seq1 (bytes): First byte sequence.
        bytes_seq2 (bytes): Second byte sequence.

    Returns:
        bytes: The XOR result as a bytes object.
    """
    if len(bytes_seq1) != len(bytes_seq2):
        raise ValueError("Both byte sequences must be of equal length.")
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes_seq1, bytes_seq2))


def generate_xor_labels(xor_data):
    """
    Generate a comma-separated string of XOR pair labels from nested xor_data.

    This function expects a nested dictionary where:
      - The first-level keys (e.g., "p1") represent the first plaintext label.
      - The second-level keys (e.g., "p2") represent the second plaintext label.
      - The innermost dictionaries contain:
          - "name" (str): A label for the XOR operation (e.g., "x12").
          - "result": The XOR result (ignored in this function).

    It returns a single string that describes each XOR pair in the form:
      {name} = {p1} ^ {p2},
    with the last pair omitting the trailing comma.

    Example:
        xor_data = { 
            "p1": {
                "p2": {"name": "x12", "result": "..."},
                "p3": {"name": "x13", "result": "..."}
            }, 
            "p2": {
                "p3": {"name": "x23", "result": "..."}
            }
        }
        labels_str = generate_xor_labels(xor_data)
        # labels_str -> "x12 = p1 ^ p2, x13 = p1 ^ p3, x23 = p2 ^ p3"
    """
    xor_labels = []
    for p1, inner_dict in xor_data.items():
        for p2, details in inner_dict.items():
            label = f"{details['name']} = {p1} ^ {p2}"
            xor_labels.append(label)
    return ", ".join(xor_labels)


def generate_xor_data(ciphertexts):
    xor_data = {}
    for idx, ct in enumerate(ciphertexts):
        if idx + 1 == len(ciphertexts):
            break
        xor_data.setdefault(f"p{idx+1}", {})
        for jdx in range(idx + 1, len(ciphertexts)):
            xor_data.setdefault(f"p{jdx+1}", {})
            xor_data[f"p{idx+1}"][f"p{jdx+1}"] = {"name": f"x{idx+1}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}
            xor_data[f"p{jdx+1}"][f"p{idx+1}"] = {"name": f"x{idx+1}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}
    return xor_data


def generate_xor_slices(xor_data, offset, crib_len):
    """
    Generate an array of slices from XOR'd ciphertexts in a nested xor_data structure.

    This function takes a nested dictionary of XOR'd ciphertext data, where the structure is:
      {
          "p1": {
              "p2": {"name": "x12", "result": "xor_result_string"},
              "p3": {"name": "x13", "result": "xor_result_string"}
          },
          "p2": {
              "p1": {"name": "x12", "result": "xor_result_string"},
              "p3": {"name": "x23", "result": "xor_result_string"}
          },
          "p3": {
              "p1": {"name": "x13", "result": "xor_result_string"},
              "p2": {"name": "x23", "result": "xor_result_string"}
          }
      }

    The function extracts slices from the XOR'd ciphertexts (`result`), sliced from `offset`
    to `offset + crib_len`.

    Args:
        xor_data (dict): A nested dictionary of XOR'd data.
        offset (int): The starting index for the slice.
        crib_len (int): The length of the slice.

    Returns:
        list: A list of dictionaries, each containing the name and the sliced result.
              Example: [{"name": "x12", "slice": "slice_data"}, ...]
    """
    xor_slices = {}
    for outer_key in xor_data:
        xor_slices.setdefault(outer_key, {})
        for inner_key, details in xor_data[outer_key].items():
            slice_result = details["result"][offset:offset + crib_len]
            xor_slices[outer_key][inner_key] = {
                "name": details["name"], "slice": slice_result}
    # print(xor_slices)
    return xor_slices


def substring_in_xor_slices(xor_slices, substring, n):
    """
    Check if a substring exists in XOR results sharing a common number.

    Args:
        xor_slices (list): A list of dictionaries with keys:
                           - "name": The XOR pair name (e.g., "x12").
                           - "slice": The XOR result as a byte string.
        substring (str): The substring to search for (in string format).
        n (int): The total number of ciphertexts.

    Returns:
        bool: True if the substring exists in at least two XORs involving one plaintext.
    """
    # Decode the substring to bytes for comparison
    substring_bytes = substring.encode()

    num_to_xors = {i: [] for i in range(1, n + 1)}

    for xor_slice in xor_slices:
        xor_name = xor_slice["name"]
        xor_result = xor_slice["slice"]

        numbers = [int(x) for x in xor_name[1:]]

        for num in numbers:
            num_to_xors[num].append(xor_result)

    print(num_to_xors)

    for num, xor_list in num_to_xors.items():
        count = sum(
            1 for xor_result in xor_list if substring_bytes in xor_result)
        if count == n-1:
            return True

    return False


def potential_match(xor_slices, crib, offset, dict):
    """Check if a crib decrypts to potential matches in XOR slices.

    Args:
        xor_slices: Dictionary of XOR slices to check against
        crib: Known plaintext string to search for
        offset: Starting position to consider in the slices
        dictionary: Dictionary for validation

    Returns:
        List of dictionaries containing potential matches with their details
    """
    results = []
    for outer_key in xor_slices.keys():
        # If `crib` really is the plaintext of `outer_key` at this offset, then
        # xor(crib, slice_of(outer ^ inner)) reveals the plaintext slice of
        # every other message. Collect those revealed slices keyed by inner_key.
        derived = {}
        p_match = True
        for inner_key, details in xor_slices[outer_key].items():
            pt_slice = xor(details["slice"], crib)
            pt_words = pt_slice.split()
            for idx, word in enumerate(pt_words):
                if not idx:
                    p_match = valid_string(send_command, pt_slice, word, dict)
                else:
                    p_match = valid_string(
                        send_command, pt_slice, word, dict, "prefix")
                if p_match == False:
                    break
            if not p_match:
                break
            derived[inner_key] = pt_slice
        if p_match:
            results.append({
                "crib": crib.decode("utf-8", "replace"),
                "plaintext": outer_key,
                "start": offset,
                "end": offset + len(crib),
                # Revealed plaintext slices of the other messages, ready to be
                # aggregated during reconstruction.
                "derived": {
                    k: v.decode("utf-8", "replace") for k, v in derived.items()
                },
            })
            print(
                f"{crib} is potentially a string in {outer_key} at index [{offset}:{offset+len(crib)}]!")
            print(list(derived.values()))
    return results
