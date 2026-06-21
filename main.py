from utils import load_words, load_short_words, read_ciphertexts, split_set
from xor_helpers import xor
from decrypt import auto_crib_drag
from reconstruct import write_report
from expand import iterative_recover
from pprint import pprint
import time
import psutil  # type: ignore
import os
from multiprocessing import Pool, Lock, Value

# Lower the priority of the process
p = psutil.Process(os.getpid())
p.nice(psutil.IDLE_PRIORITY_CLASS)  # On Windows


def main():
    """
    The main entry point:
      - Read the ciphertexts
      - Attempt automatic crib-dragging
      - Attempt automatic combination testing
      - Jump to the interactive approach at user request
    """
    num_processes = os.cpu_count()

    filename = "ciphertexts.txt"
    ciphertexts = read_ciphertexts(filename)
    # The .10 tier (most common words) supplies cribs; english-words.all is the
    # full dictionary used for validation and word completion -- it matches the
    # word list the C++ trie loads, and is leaner/cleaner than the tier union
    # (which pulls in obscure inflections that create false candidates).
    cribs_dict = load_words('dictionary/english-words.10')
    full_dict = load_words('dictionary/english-words.all')
    # Short words let the token validator segment patterns like 'of?ej'.
    full_dict |= load_short_words('dictionary/english-words.all')

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

    # Minimum crib length to drag. Shorter cribs recover far more of the message
    # but add noise; corroboration (MIN_VOTES) plus the iterative word-completion
    # pass clean most of it up. Measured trade-off on a 3-ciphertext sample:
    #   len>=5 -> ~23% recovered (cleanest)
    #   len>=4 -> ~43% recovered (good balance, default)
    #   len>=3 -> ~68% recovered (most coverage, noisiest)
    MIN_CRIB_LEN = 4
    # A keystream byte backed by a single crib match is an unverified guess.
    # Require this many agreeing matches before accepting a byte. Lower to 1 for
    # more (noisier) coverage; raise it for fewer, higher-confidence bytes.
    MIN_VOTES = 2

    start_time = time.perf_counter()
    cribs = {w for w in cribs_dict if len(w) >= MIN_CRIB_LEN}
    split_sets = split_set(cribs, num_processes)
    with Pool(processes=num_processes) as pool:
        tasks = [
            (split_sets[i], xor_data, len_ct, len(ciphertexts), full_dict)
            for i in range(num_processes)
        ]
        results = pool.starmap(auto_crib_drag, tasks)
        all_matches = []
        for matches in results:
            all_matches.extend(matches)
        # Sort for determinism: the worker split iterates a set, so match order
        # (and thus vote tie-breaking) would otherwise vary between runs.
        all_matches.sort(key=lambda m: (m["plaintext"], m["start"], m["crib"]))
        print(f"Found {len(all_matches)} total potential matches!")

    # Aggregate the matches into a keystream, then iteratively extend and
    # spell-correct the recovered words until the result stops growing.
    print("Reconstructing and expanding...")
    result = iterative_recover(all_matches, ciphertexts, full_dict,
                               min_votes=MIN_VOTES, interactive=True)
    print(f"Recovered {result['recovered']}/{result['length']} keystream bytes "
          f"({result['corroborated']} corroborated by >=2 matches).")
    for idx, pt in enumerate(result["plaintexts"], start=1):
        print(f"P{idx}: {pt}")
    report_path = write_report(result, ciphertexts)
    print(f"Wrote full reconstruction report to {report_path}")
    # auto_crib_drag(split_sets[0], xor_data, len_ct, len(ciphertexts), words[6])
    end_time = time.perf_counter()
    print(f"Execution time: {end_time - start_time:.6f} seconds")


if __name__ == "__main__":
    main()
