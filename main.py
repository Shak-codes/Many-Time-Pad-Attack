from utils import load_words, read_ciphertexts, split_set
from xor_helpers import xor
from decrypt import auto_crib_drag
from pprint import pprint
import time
import psutil  # type: ignore
import os
from multiprocessing import Pool, Lock, Value

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
    words.append(set().union(*words))

    return words


def main():
    """
    The main entry point:
      - Read the ciphertexts
      - Attempt automatic crib-dragging
      - Attempt automatic combination testing
      - Jump to the interactive approach at user request
    """
    num_processes = os.cpu_count()  # Number of processes

    filename = "ciphertexts.txt"
    ciphertexts = read_ciphertexts(filename)
    words = construct_dict()

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
        if f"p{idx+1}" not in xor_data:
            xor_data[f"p{idx+1}"] = {}
        for jdx in range(idx + 1, len(ciphertexts)):
            if f"p{jdx+1}" not in xor_data:
                xor_data[f"p{jdx+1}"] = {}
            if f"p{jdx+1}" not in xor_data[f"p{idx+1}"]:
                xor_data[f"p{idx+1}"][f"p{jdx+1}"] = {}
            xor_data[f"p{idx+1}"][f"p{jdx+1}"] = {"name": f"x{idx+1}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}
            xor_data[f"p{jdx+1}"][f"p{idx+1}"] = {"name": f"x{idx+1}{jdx+1}",
                                                  "result": xor(ct, ciphertexts[jdx])}

    pprint(xor_data)

    start_time = time.perf_counter()
    split_sets = split_set(words[0], num_processes)
    with Pool(processes=num_processes) as pool:
        tasks = [
            (split_sets[i], xor_data, len_ct, len(ciphertexts), words[6])
            for i in range(num_processes)
        ]
        results = pool.starmap(auto_crib_drag, tasks)
        total_matches = 0
        for matches in results:
            total_matches += matches
        print(f"Found {total_matches} total potential matches!")
    # auto_crib_drag(words[0], xor_data, len_ct, len(ciphertexts), words[6])
    end_time = time.perf_counter()
    print(f"Execution time: {end_time - start_time:.6f} seconds")


if __name__ == "__main__":
    main()
