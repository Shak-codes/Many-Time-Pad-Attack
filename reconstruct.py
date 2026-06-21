from collections import Counter, defaultdict

# Placeholders used when rendering plaintexts for display.
UNKNOWN = "_"       # keystream byte at this position was never recovered
NONPRINT = "."      # keystream is known but the decrypted byte isn't printable


def _plaintext_index(label):
    """Convert a plaintext label like 'p3' into a zero-based index (2)."""
    return int(label[1:]) - 1


def collect_keystream_votes(matches, ciphertexts):
    """
    Turn crib-drag matches into per-position votes for the shared keystream.

    Because the same keystream encrypts every message, a single match fully
    determines the keystream over its range: if `crib` is the plaintext of
    message `plaintext` at [start:end], then

        K[pos] = C[plaintext][pos] ^ crib[pos]

    Every match contributes such a hypothesis. Overlapping true matches agree
    on the same key byte and reinforce each other; scattered false positives
    cast lone, low-count votes.

    Returns:
        dict[int, Counter]: position -> Counter of {key_byte: vote_count}.
    """
    votes = defaultdict(Counter)
    for m in matches:
        ct = ciphertexts[_plaintext_index(m["plaintext"])]
        crib = m["crib"].encode("utf-8")
        for i, crib_byte in enumerate(crib):
            pos = m["start"] + i
            if pos < len(ct):
                votes[pos][ct[pos] ^ crib_byte] += 1
    return votes


def recover_keystream(votes, length, min_votes=1):
    """
    Pick the winning key byte at each position by majority vote.

    Args:
        votes: output of collect_keystream_votes.
        length: total keystream length to reconstruct.
        min_votes: minimum number of agreeing votes required to accept a byte.

    Returns:
        (key, known, confidence)
          key        - bytes of length `length` (0 where unknown)
          known      - list[bool], True where a byte was accepted
          confidence - list[float], winning_votes / total_votes per position
    """
    key = bytearray(length)
    known = [False] * length
    confidence = [0.0] * length

    for pos, counter in votes.items():
        if pos >= length or not counter:
            continue  # no votes (e.g. all retracted) -> position stays unknown
        key_byte, winning = counter.most_common(1)[0]
        if winning < min_votes:
            continue
        key[pos] = key_byte
        known[pos] = True
        confidence[pos] = winning / sum(counter.values())

    return bytes(key), known, confidence


def decrypt_with_keystream(ciphertexts, key, known):
    """
    Decrypt every ciphertext with the (partial) recovered keystream.

    Unknown positions become UNKNOWN; known-but-unprintable bytes become
    NONPRINT, so a reader can distinguish "no data" from "noise".

    Returns:
        list[str]: one rendered plaintext per ciphertext.
    """
    rendered = []
    for ct in ciphertexts:
        chars = []
        for pos in range(len(ct)):
            if pos < len(key) and known[pos]:
                byte = ct[pos] ^ key[pos]
                chars.append(chr(byte) if 32 <= byte < 127 else NONPRINT)
            else:
                chars.append(UNKNOWN)
        rendered.append("".join(chars))
    return rendered


def find_conflicts(votes, threshold=0.6):
    """
    Report positions where the winning key byte is contested.

    A position is a conflict when the top candidate holds less than `threshold`
    of the votes (i.e. competing matches disagree about the keystream there).

    Returns:
        list[dict]: {position, candidates: [(key_byte, count), ...]} sorted by
        position, useful for manually adjudicating ambiguous spots.
    """
    conflicts = []
    for pos in sorted(votes):
        counter = votes[pos]
        if not counter:
            continue  # no votes (e.g. all retracted)
        total = sum(counter.values())
        winning = counter.most_common(1)[0][1]
        if total > 1 and winning / total < threshold:
            conflicts.append({
                "position": pos,
                "candidates": counter.most_common(),
            })
    return conflicts


def reconstruct(matches, ciphertexts, min_votes=1):
    """
    Full reconstruction pass: votes -> keystream -> decrypted plaintexts.

    Returns a result dict with the recovered keystream, rendered plaintexts,
    coverage statistics, and contested positions.
    """
    length = max((len(ct) for ct in ciphertexts), default=0)
    votes = collect_keystream_votes(matches, ciphertexts)
    key, known, confidence = recover_keystream(votes, length, min_votes)
    plaintexts = decrypt_with_keystream(ciphertexts, key, known)
    conflicts = find_conflicts(votes)

    recovered = sum(known)
    # Positions backed by two or more agreeing matches are far more trustworthy.
    corroborated = sum(1 for pos, c in votes.items()
                       if pos < length and c.most_common(1)[0][1] >= 2)

    return {
        "key": key,
        "known": known,
        "confidence": confidence,
        "plaintexts": plaintexts,
        "conflicts": conflicts,
        "length": length,
        "recovered": recovered,
        "corroborated": corroborated,
    }


def write_report(result, ciphertexts, path="recovered.txt"):
    """Write a human-readable reconstruction report to `path`."""
    key, known = result["key"], result["known"]
    length = result["length"]

    # Keystream as hex, with '??' marking bytes we never recovered.
    key_hex = " ".join(
        f"{key[pos]:02x}" if known[pos] else "??" for pos in range(length))

    lines = []
    lines.append("=== Reconstruction report ===")
    pct = (100 * result["recovered"] / length) if length else 0
    lines.append(
        f"Keystream bytes recovered: {result['recovered']} / {length} ({pct:.1f}%)")
    lines.append(
        f"  of which corroborated (>=2 agreeing matches): {result['corroborated']}")
    lines.append(f"Contested positions: {len(result['conflicts'])}")
    lines.append("")

    lines.append("=== Recovered keystream (hex, '??' = unknown) ===")
    lines.append(key_hex)
    lines.append("")

    lines.append(f"=== Reconstructed plaintexts "
                 f"('{UNKNOWN}' = unknown, '{NONPRINT}' = unprintable) ===")
    for idx, pt in enumerate(result["plaintexts"], start=1):
        lines.append(f"P{idx}: {pt}")
    lines.append("")

    if result["conflicts"]:
        lines.append("=== Contested positions (key byte: votes) ===")
        for c in result["conflicts"]:
            cands = ", ".join(f"0x{b:02x}:{n}" for b, n in c["candidates"])
            lines.append(f"  pos {c['position']}: {cands}")

    with open(path, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")

    return path
