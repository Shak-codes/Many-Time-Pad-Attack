from utils import load_words, read_ciphertexts
from xor_helpers import xor
from decrypt import auto_crib_drag
from pprint import pprint
import time
from GeneralizedSuffixArray.GeneralizedSuffixArray import GeneralizedSuffixArray
from GeneralizedSuffixArray.utils import save_suffix_array
import psutil
import os

# Lower the priority of the process
p = psutil.Process(os.getpid())
p.nice(psutil.IDLE_PRIORITY_CLASS)  # On Windows


def construct_dict():
    words = []

    word_path = 'dictionary/english-words'
    words.append(load_words(f'{word_path}.10', words))
    words.append(load_words(f'{word_path}.20', words))
    words.append(load_words(f'{word_path}.35', words))
    words.append(load_words(f'{word_path}.50', words))
    words.append(load_words(f'{word_path}.70', words))
    words.append(load_words(f'{word_path}.95', words))

    return words


def main():
    """
    The main entry point:
      - Read the ciphertexts
      - Attempt automatic crib-dragging
      - Attempt automatic combination testing
      - Jump to the interactive approach at user request
    """
    filename = "ciphertexts.txt"
    ciphertexts = read_ciphertexts(filename)
    words = construct_dict()
    print(f"Constructing GSA")
    start_time = time.perf_counter()
    gsa = GeneralizedSuffixArray(words[4])
    end_time = time.perf_counter()
    print(f"Completed in: {end_time - start_time:.6f} seconds")

    save_suffix_array(gsa.suffix_array, gsa.words,
                      f"GeneralizedSuffixArray/suffix_array4.pkl")

    if len(ciphertexts) < 2:
        print("Need at least two ciphertexts. Exiting.")
        return

    print(f"Loaded {len(ciphertexts)} ciphertexts from {filename}.")
    for idx, ct in enumerate(ciphertexts, start=1):
        len_ct = len(ct)
        print(f"   {idx}. Ciphertext #{idx}, length={len(ct)} bytes")

    # XOR the ciphertexts together
    xor_data = {}
    for idx, ct in enumerate(ciphertexts):
        if idx + 1 == len(ciphertexts):
            break
        xor_data[f"p{idx+1}"] = {}
        for jdx in range(idx + 1, len(ciphertexts)):
            xor_data[f"p{idx+1}"][f"p{jdx+1}"] = {"name": f"x{jdx}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}

    pprint(xor_data)
    # Begin automatic crib dragging
    auto_crib_drag(words[0], xor_data, len_ct, gsa)


if __name__ == "__main__":
    main()
