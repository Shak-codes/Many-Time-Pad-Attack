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
              "p3": {"name": "x23", "result": "xor_result_string"}
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
    xor_slices = []
    for inner_dict in xor_data.values():
        for details in inner_dict.values():
            # Extract the slice from the XOR'd result
            slice_result = details["result"][offset:offset + crib_len]
            xor_slices.append({"name": details["name"], "slice": slice_result})
    return xor_slices
