from xor_helpers import generate_xor_labels, generate_xor_slices, xor
from utils import is_printable_ascii
from pprint import pprint
from GeneralizedSuffixArray.GeneralizedSuffixArray import GeneralizedSuffixArray
import string


def auto_crib_drag(words, xor_data, len_ct, suffix_array):
    """
    Automatically crib drags words over the XOR'd ciphertexts.
    There are three scenarios we could come across during this,
    either the program.
        a. deciphers entire words in the plaintexts.
        b. deciphers portions of words in the plaintexts.
        c. yields complete gibberish.
    """
    labels = generate_xor_labels(xor_data)

    for word in sorted(words):
        crib = word.encode("utf-8")
        crib_len = len(crib)
        max_offset = len_ct - crib_len + 1

        # Debugging purposes
        # print(f"Crib dragging '{crib}' across {labels}")
        matches = []

        for offset in range(max_offset):
            xor_slices = generate_xor_slices(xor_data, offset, crib_len)
            potential_match = True
            for slice_data in xor_slices:
                plaintext = xor(slice_data["slice"], crib)
                pt_words = plaintext.split()
                if crib.decode("utf-8") == "grasshopper" and offset == 91:
                    print(f"crib: {crib} - length: {crib_len}")
                    print(f"offset: {offset}")
                    print(f"slice: {slice_data["name"]} - length: {len(slice_data["slice"])}")
                    print(f"Plaintext: {plaintext}\n")
                for word in pt_words:
                    if crib.decode("utf-8") == "grasshopper" and offset == 91:
                        print(
                            f"Is {word} a substring of another word? Answer: {suffix_array.substring_exists(word)}")
                    if not is_printable_ascii(word) or not suffix_array.substring_exists(word):
                        potential_match = False
                        break
                    if crib.decode("utf-8") == "grasshopper" and offset == 91:
                        print(f"{word} is a substring of another word!")
            if potential_match:
                print(
                    f"{crib} is a potential match at index [{offset}:{offset+crib_len}]!")
                break
    print("Finished looking for potential matches!")
