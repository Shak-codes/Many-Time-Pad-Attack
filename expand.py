import string
from collections import defaultdict

from reconstruct import (collect_keystream_votes, recover_keystream,
                         decrypt_with_keystream, find_conflicts)

# Characters that may legitimately appear in a recovered plaintext.
ALLOWED = set(string.ascii_letters + " " + "!,.:;'\"?")
# Characters that make up a "word" (used to delimit fragments).
WORDCHARS = set(string.ascii_letters + "'")
# Tokens longer than this are left unvalidated (too sparse to constrain cheaply).
MAX_TOKEN = 30


class WordIndex:
    """
    Dictionary with length buckets and a lazy (length, position, char) index.

    The position index turns "does any word match these fixed letters" and
    "which words match" from a full bucket scan into a small set intersection,
    which is the dominant cost during expansion. Everything is lowercase so it
    is case-insensitive (capitalised words validate against lowercase entries).
    """

    def __init__(self, words):
        self._set = set(words)
        self.by_len = defaultdict(list)
        for w in self._set:
            self.by_len[len(w)].append(w)
        self._pos = {}              # length -> {(pos, char): set(words)}, built lazily
        self._wmatch_cache = {}
        self._tokensat_cache = {}

    def is_word(self, w):
        return w.lower() in self._set

    def _pos_index(self, length):
        idx = self._pos.get(length)
        if idx is None:
            idx = defaultdict(set)
            for w in self.by_len.get(length, ()):
                for i, ch in enumerate(w):
                    idx[(i, ch)].add(w)
            self._pos[length] = idx
        return idx

    def words_matching(self, length, constraints):
        """Set of length-`length` words satisfying every (pos, lowercase-char)."""
        if not constraints:
            return set(self.by_len.get(length, ()))
        idx = self._pos_index(length)
        lists = []
        for pos, ch in constraints:
            s = idx.get((pos, ch))
            if not s:
                return set()
            lists.append(s)
        lists.sort(key=len)
        result = set(lists[0])
        for s in lists[1:]:
            result &= s
            if not result:
                break
        return result

    def candidates(self, length, constraints, max_err):
        """Words matching `constraints` with up to `max_err` (0 or 1) mismatches."""
        result = self.words_matching(length, constraints)
        if max_err >= 1 and constraints:
            result = set(result)
            for j in range(len(constraints)):
                result |= self.words_matching(length,
                                              constraints[:j] + constraints[j + 1:])
        return result

    def word_matches(self, pattern):
        """True if some dict word of len(pattern) matches it (None = wildcard)."""
        key = tuple(ch.lower() if ch is not None else None for ch in pattern)
        cached = self._wmatch_cache.get(key)
        if cached is not None:
            return cached
        constraints = [(i, ch) for i, ch in enumerate(key) if ch is not None]
        length = len(key)
        if not constraints:
            result = bool(self.by_len.get(length))
        else:
            idx = self._pos_index(length)
            lists = []
            result = True
            for pos, ch in constraints:
                s = idx.get((pos, ch))
                if not s:
                    result = False
                    break
                lists.append(s)
            if result and len(lists) > 1:
                lists.sort(key=len)
                # Probe the smallest posting list against the others (no copy).
                result = any(all(w in s for s in lists[1:]) for w in lists[0])
        self._wmatch_cache[key] = result
        return result

    def token_satisfiable(self, cells):
        """
        True if a token can be filled into real words.

        `cells` is a tuple of known letters and None (unknown). Each unknown may
        become any letter or a single space, so the token must split into
        dictionary words. This checks the *whole* token, not just the run around
        one cell -- so 'af?ej' (no 5-letter word, and 'af'/'ej' aren't words) is
        correctly rejected. Case-insensitive.
        """
        cells = tuple(c.lower() if c is not None else None for c in cells)
        cached = self._tokensat_cache.get(cells)
        if cached is not None:
            return cached
        m = len(cells)
        if m > MAX_TOKEN:
            return True  # too long/sparse to constrain affordably
        memo = {}

        def segment(i):
            if i == m:
                return True
            if i in memo:
                return memo[i]
            ok = False
            for j in range(i + 1, m + 1):
                if self.word_matches(cells[i:j]):
                    if j == m:
                        ok = True
                        break
                    if cells[j] is None and segment(j + 1):  # unknown acts as space
                        ok = True
                        break
            memo[i] = ok
            return ok

        result = segment(0)
        self._tokensat_cache[cells] = result
        return result


def _decrypt_chars(ct, key, known):
    """Decrypt a ciphertext into a list of chars (None where keystream unknown)."""
    chars = []
    for pos in range(len(ct)):
        if pos < len(key) and known[pos]:
            byte = ct[pos] ^ key[pos]
            chars.append(chr(byte) if 32 <= byte < 127 else None)
        else:
            chars.append(None)
    return chars


def _token_bounds(chars, overrides, pos):
    """
    Bounds [a, b] of the token containing `pos`: the maximal span of letters and
    unknowns delimited by a known space/punctuation or the message edge. Unknowns
    stay inside (they may turn out to be letters or spaces). Returns (None, None)
    if `pos` itself is a known boundary character.
    """
    def eff(p):
        return overrides[p] if p in overrides else chars[p]

    c = eff(pos)
    if c is not None and c not in WORDCHARS:
        return None, None  # pos is a space/punctuation boundary
    a = b = pos
    while a - 1 >= 0:
        cc = eff(a - 1)
        if cc is None or cc in WORDCHARS:
            a -= 1
        else:
            break
    while b + 1 < len(chars):
        cc = eff(b + 1)
        if cc is None or cc in WORDCHARS:
            b += 1
        else:
            break
    return a, b


def _cross_message_ok(proposal, plains, ciphertexts, source, index):
    """
    A proposed set of keystream bytes must keep *every other* message valid: each
    revealed character must be allowed, and every token the change touches must
    still be fillable into real dictionary words. Validating the whole token (not
    just the letters immediately around the change) is what rules out impossible
    options like 'af?ej'.
    """
    for j, ct in enumerate(ciphertexts):
        if j == source:
            continue
        chars = plains[j]
        overrides = {}
        for pos, (key_byte, _) in proposal.items():
            if pos >= len(ct):
                continue
            byte = ct[pos] ^ key_byte
            if not (32 <= byte < 127):
                return False
            c = chr(byte)
            if c not in ALLOWED:
                return False
            overrides[pos] = c
        # A changed cell that became a letter sits inside its own token; one that
        # became a space/punctuation closes the tokens on either side of it.
        probes = set()
        for pos, c in overrides.items():
            if c in WORDCHARS:
                probes.add(pos)
            else:
                probes.update((pos - 1, pos + 1))
        checked = set()
        for q in probes:
            if not (0 <= q < len(chars)):
                continue
            a, b = _token_bounds(chars, overrides, q)
            if a is None or (a, b) in checked:
                continue
            checked.add((a, b))
            cells = []
            for p in range(a, b + 1):
                ch = overrides[p] if p in overrides else chars[p]
                cells.append(ch if ch in WORDCHARS else None)
            if not index.token_satisfiable(tuple(cells)):
                return False
    return True


def _proposal_for_word(chars, ct, word, word_start):
    """
    Keystream bytes implied by placing `word` at `word_start`.

    Each entry is pos -> (key_byte, is_correction): a fill where the position was
    unknown, or a correction where it overrides a previously decrypted char.
    Returns None if the word would collide with a non-word character.
    """
    proposal = {}
    for k, ch in enumerate(word):
        pos = word_start + k
        cur = chars[pos]
        if cur is None:
            proposal[pos] = (ct[pos] ^ ord(ch), False)
        elif cur.lower() == ch.lower():
            continue  # same letter (ignoring case) -> keep existing byte
        elif cur in WORDCHARS:
            proposal[pos] = (ct[pos] ^ ord(ch), True)
        else:
            return None  # word disagrees with punctuation/space -> impossible
    return proposal


def _maybe_capital(chars, word_start):
    """
    Whether a word starting at `word_start` could be capitalised -- i.e. it sits
    at a sentence start (message start, after a sentence-ending mark, or in
    unknown context). Used to also try a capital-first-letter candidate there.
    """
    if word_start <= 0:
        return True
    prev = chars[word_start - 1]
    if prev is None or prev in '.?!"\'':
        return True
    if prev == ' ':
        pp = chars[word_start - 2] if word_start - 2 >= 0 else None
        return pp is None or pp in '.?!"'
    return False


def _candidate_forms(word, chars, word_start):
    """A dictionary word plus, where plausible, its capital-first-letter form."""
    forms = [word]
    if word and word[0].isalpha() and _maybe_capital(chars, word_start):
        forms.append(word[0].upper() + word[1:])
    return forms


# --- candidate enumeration ------------------------------------------------
# Each solver returns a list of "survivor" records: {word, start, proposal}.
# A record means "placing `word` at `start` keeps every other message valid".


def _delimited_candidates(chars, t_start, t_end, ct, index, plains,
                          ciphertexts, source, max_err):
    """Words that fit a fixed-length, space-delimited token (<= max_err fixes)."""
    pat = chars[t_start:t_end + 1]
    if any(c is not None and c not in WORDCHARS for c in pat):
        return []  # token contains punctuation -> not a single word
    known_idx = [(i, c) for i, c in enumerate(pat) if c is not None]
    if not known_idx:
        return []
    word_now = "".join(c for _, c in known_idx)
    if len(known_idx) == len(pat) and index.is_word(word_now):
        return []  # already a valid word
    budget = max_err if len(known_idx) >= 4 else 0
    constraints = [(i, c.lower()) for i, c in known_idx]

    survivors = []
    for w in index.candidates(len(pat), constraints, budget):
        for cand in _candidate_forms(w, chars, t_start):
            prop = _proposal_for_word(chars, ct, cand, t_start)
            if prop and _cross_message_ok(prop, plains, ciphertexts, source, index):
                survivors.append({"word": cand, "start": t_start, "proposal": prop})
    return survivors


def _open_candidates(chars, start, end, ct, index, plains, ciphertexts, source,
                     forward):
    """Words that extend a one-side-anchored fragment via prefix/suffix match."""
    frag = chars[start:end + 1]
    if any(c is None or c not in WORDCHARS for c in frag):
        return []
    f = len(frag)
    frag_lower = [c.lower() for c in frag]
    budget = 1 if f >= 6 else 0

    gap = 0
    p = end + 1 if forward else start - 1
    step = 1 if forward else -1
    while 0 <= p < len(chars) and chars[p] is None:
        gap += 1
        p += step

    survivors = []
    for length in range(f, f + gap + 1):
        word_start = start if forward else end - length + 1
        if word_start < 0:
            continue
        boundary = word_start + length if forward else word_start - 1
        if 0 <= boundary < len(chars):
            bc = chars[boundary]
            if bc is not None and bc in WORDCHARS:
                continue  # word would run into a known continuing letter
        if forward:
            constraints = [(i, frag_lower[i]) for i in range(f)]
        else:
            constraints = [(length - f + i, frag_lower[i]) for i in range(f)]
        for w in index.candidates(length, constraints, budget):
            for cand in _candidate_forms(w, chars, word_start):
                prop = _proposal_for_word(chars, ct, cand, word_start)
                if prop and _cross_message_ok(prop, plains, ciphertexts, source, index):
                    survivors.append({"word": cand, "start": word_start, "proposal": prop})
    return survivors


def _floating_candidates(chars, start, end, ct, index, plains, ciphertexts,
                         source):
    """Words that *contain* a fragment bounded by unknowns on both sides."""
    frag = chars[start:end + 1]
    if any(c is None or c not in WORDCHARS for c in frag):
        return []
    f = len(frag)
    if f < 3:
        return []
    frag_lower = [c.lower() for c in frag]
    budget = 1 if f >= 5 else 0

    gl = 0
    p = start - 1
    while p >= 0 and chars[p] is None and gl < 6:
        gl += 1
        p -= 1
    gr = 0
    p = end + 1
    while p < len(chars) and chars[p] is None and gr < 6:
        gr += 1
        p += 1

    survivors = []
    for length in range(f, f + gl + gr + 1):
        for offset in range(0, length - f + 1):
            word_start = start - offset
            word_end = word_start + length - 1
            if word_start < start - gl or word_start < 0:
                continue
            if word_end > end + gr or word_end < end:
                continue
            bl = word_start - 1
            if bl >= 0 and chars[bl] is not None and chars[bl] in WORDCHARS:
                continue
            br = word_end + 1
            if br < len(chars) and chars[br] is not None and chars[br] in WORDCHARS:
                continue
            constraints = [(offset + i, frag_lower[i]) for i in range(f)]
            for w in index.candidates(length, constraints, budget):
                for cand in _candidate_forms(w, chars, word_start):
                    prop = _proposal_for_word(chars, ct, cand, word_start)
                    if prop and _cross_message_ok(prop, plains, ciphertexts, source, index):
                        survivors.append({"word": cand, "start": word_start, "proposal": prop})
    return survivors


def _closed_tokens(chars):
    """Yield (start, end) of regions bounded by known spaces or message edges."""
    n = len(chars)
    bounds = [-1] + [p for p in range(n) if chars[p] == " "] + [n]
    for a, b in zip(bounds, bounds[1:]):
        if a + 1 <= b - 1:
            yield a + 1, b - 1


def _fragments(chars):
    """Yield (start, end) of maximal known word-character runs."""
    n = len(chars)
    p = 0
    while p < n:
        if chars[p] is not None and chars[p] in WORDCHARS:
            start = p
            while p + 1 < n and chars[p + 1] is not None and chars[p + 1] in WORDCHARS:
                p += 1
            yield start, p
        p += 1


def _each_spot(plains, ciphertexts, index, max_err):
    """
    Yield (source, start, end, survivors) for every token/fragment that has at
    least one surviving candidate, across all messages. Shared by the automatic
    loop (which commits agreement) and the interactive loop (which presents
    disagreement).
    """
    for source, ct in enumerate(ciphertexts):
        chars = plains[source]
        for t_start, t_end in _closed_tokens(chars):
            surv = _delimited_candidates(chars, t_start, t_end, ct, index,
                                         plains, ciphertexts, source, max_err)
            if surv:
                yield source, t_start, t_end, surv
        for start, end in _fragments(chars):
            lc = chars[start - 1] if start > 0 else None
            rc = chars[end + 1] if end < len(chars) - 1 else None
            left = start == 0 or (lc is not None and lc not in WORDCHARS)
            right = end == len(chars) - 1 or (rc is not None and rc not in WORDCHARS)
            if left and not right:
                surv = _open_candidates(chars, start, end, ct, index, plains,
                                        ciphertexts, source, True)
            elif right and not left:
                surv = _open_candidates(chars, start, end, ct, index, plains,
                                        ciphertexts, source, False)
            elif not left and not right:
                surv = _floating_candidates(chars, start, end, ct, index,
                                            plains, ciphertexts, source)
            else:
                surv = []
            if surv:
                yield source, start, end, surv


def _commit(proposals, votes, committed, blocked, fill_w, corr_w):
    """
    Commit the keystream bytes that *all* candidate proposals agree on.

    Disagreements are left unresolved (for a later pass or the interactive
    layer). `committed` tracks already-applied (pos, byte) pairs so re-deriving
    the same answer doesn't count as progress and the loop can terminate.
    `blocked` holds (pos -> bytes) that retraction has ruled out; those are never
    re-committed, forcing a different answer to be found.
    """
    if not proposals:
        return 0
    common = set(proposals[0])
    for p in proposals[1:]:
        common &= set(p)

    added = 0
    for pos in common:
        bytes_here = {p[pos][0] for p in proposals}
        if len(bytes_here) != 1:
            continue  # candidates disagree on the byte -> don't guess
        key_byte = next(iter(bytes_here))
        if key_byte in blocked.get(pos, ()):
            continue  # this value was retracted as contradictory
        is_corr = any(p[pos][1] for p in proposals)
        votes[pos][key_byte] += corr_w if is_corr else fill_w
        if (pos, key_byte) not in committed:
            committed.add((pos, key_byte))
            added += 1
    return added


def _auto_passes(votes, ciphertexts, index, length, committed, blocked,
                 min_votes, fill_w, corr_w, max_err, max_passes, log):
    """Run the automatic complete/correct passes until nothing new is committed."""
    for npass in range(1, max_passes + 1):
        # Read the working view at the same confidence threshold we commit at.
        # Reading at a *lower* threshold lets a weak single-vote byte form a
        # spurious complete word (e.g. 'fade'), which then blocks extending the
        # real fragment ('de' -> 'made') -- and the weak byte is dropped from the
        # final output anyway, leaving the fragment stuck.
        key, known, _ = recover_keystream(votes, length, min_votes)
        plains = [_decrypt_chars(ct, key, known) for ct in ciphertexts]
        added = 0
        for _, _, _, surv in _each_spot(plains, ciphertexts, index, max_err):
            added += _commit([r["proposal"] for r in surv], votes, committed,
                             blocked, fill_w, corr_w)
        recovered = sum(recover_keystream(votes, length, min_votes)[1])
        log(f"  pass {npass}: +{added} new bytes, "
            f"{recovered}/{length} keystream bytes recovered")
        if added == 0:
            break


# --- interactive layer (level 1: choose among valid candidates) -----------


def _disagreed_positions(survivors):
    """Positions where the candidates do not all imply the same keystream byte."""
    pos_bytes = defaultdict(set)
    for r in survivors:
        for pos, (byte, _) in r["proposal"].items():
            pos_bytes[pos].add(byte)
    return frozenset(pos for pos, bs in pos_bytes.items() if len(bs) > 1)


def gather_decisions(plains, ciphertexts, index, max_err, max_options):
    """
    Collect the ambiguous spots: tokens/fragments where several words survive
    cross-message validation but disagree on the keystream. Each decision lists
    its distinct candidate records for the user to choose between.
    """
    decisions = []
    seen = set()
    for source, start, end, surv in _each_spot(plains, ciphertexts, index, max_err):
        disagreed = _disagreed_positions(surv)
        if not disagreed:
            continue  # candidates agree -> the automatic loop handles it
        # Keep one record per distinct word.
        options, words = [], set()
        for r in sorted(surv, key=lambda r: r["word"]):
            if r["word"] not in words:
                words.add(r["word"])
                options.append(r)
        if not (2 <= len(options) <= max_options):
            continue  # nothing to choose, or too ambiguous to be useful
        if disagreed in seen:
            continue  # same keystream ambiguity already queued from another message
        seen.add(disagreed)
        decisions.append({"source": source, "start": start, "end": end,
                          "options": options, "key": disagreed})
    return decisions


def _render_window(plains, ciphertexts, proposal, lo, hi):
    """Render every message over [lo, hi] with a candidate's keystream applied."""
    rendered = []
    for j, ct in enumerate(ciphertexts):
        chars = []
        for p in range(lo, hi + 1):
            if p in proposal:
                byte = ct[p] ^ proposal[p][0]
                chars.append(chr(byte) if 32 <= byte < 127 else "?")
            elif plains[j][p] is not None:
                chars.append(plains[j][p])
            else:
                chars.append("_")
        rendered.append("".join(chars))
    return rendered


def _present_and_choose(decision, plains, ciphertexts, remaining, prompt=input):
    """
    Show a single ambiguity and its candidate words (with how each makes all
    messages read), then read the user's choice. Returns an option index, or the
    string 'skip' / 'quit'.
    """
    source, start, end = decision["source"], decision["start"], decision["end"]
    lo = max(0, start - 12)
    hi = min(len(plains[0]) - 1, end + 12)
    print()
    print(f"[{remaining} ambiguous spot(s) left] Message P{source + 1}, "
          f"columns {start}-{end} could be several words:")
    for i, rec in enumerate(decision["options"], start=1):
        rendered = _render_window(plains, ciphertexts, rec["proposal"], lo, hi)
        print(f"  [{i}] {rec['word']!r}")
        for j, line in enumerate(rendered, start=1):
            marker = "  <-" if j - 1 == source else ""
            print(f"        P{j}: {line}{marker}")
    print("  [s] skip this one   [q] stop resolving")
    while True:
        try:
            choice = prompt("Choose option #: ").strip().lower()
        except EOFError:
            return "quit"
        if choice in ("q", "quit"):
            return "quit"
        if choice in ("s", "skip", ""):
            return "skip"
        if choice.isdigit() and 1 <= int(choice) <= len(decision["options"]):
            return int(choice) - 1
        print("  Please enter an option number, 's' to skip, or 'q' to quit.")


def _force(votes, committed, record, weight):
    """Force-commit the chosen candidate's keystream bytes so they win the vote."""
    for pos, (byte, _) in record["proposal"].items():
        votes[pos][byte] += weight
        committed.add((pos, byte))


def _interactive_loop(votes, ciphertexts, index, length, committed, blocked,
                      min_votes, fill_w, corr_w, max_err, max_passes,
                      max_options, log, prompt=input):
    """
    Present ambiguous words one at a time. After each choice, re-run the
    automatic passes so the decision can cascade, then look for what's left.
    """
    skipped = set()
    while True:
        key, known, _ = recover_keystream(votes, length, min_votes)
        plains = [_decrypt_chars(ct, key, known) for ct in ciphertexts]
        decisions = [d for d in gather_decisions(plains, ciphertexts, index,
                                                 max_err, max_options)
                     if d["key"] not in skipped]
        if not decisions:
            print("No more ambiguous words to resolve.")
            break
        decision = decisions[0]
        action = _present_and_choose(decision, plains, ciphertexts,
                                     len(decisions), prompt=prompt)
        if action == "quit":
            break
        if action == "skip":
            skipped.add(decision["key"])
            continue
        _force(votes, committed, decision["options"][action], corr_w)
        _auto_passes(votes, ciphertexts, index, length, committed, blocked,
                     min_votes, fill_w, corr_w, max_err, max_passes,
                     lambda *a: None)


def _dead_end_tokens(plains, ciphertexts, index, max_err):
    """
    Bounded tokens whose known letters admit no cross-message-valid word.

    Two cases qualify: a fully-known token that isn't a real word and can't be
    corrected, or a tightly-bounded fragment (<=1 unknown) that can't be
    completed. Either way some committed byte in it must be wrong.
    """
    deads = []
    for src, ct in enumerate(ciphertexts):
        chars = plains[src]
        for a, b in _closed_tokens(chars):
            cells = chars[a:b + 1]
            if any(c is not None and c not in WORDCHARS for c in cells):
                continue  # contains punctuation -> not a single word
            known_cells = [c for c in cells if c is not None]
            if not known_cells:
                continue
            unknowns = len(cells) - len(known_cells)
            if unknowns > 1:
                continue  # too open to call a dead end yet
            if unknowns == 0 and index.is_word("".join(cells)):
                continue  # already a valid word
            if _delimited_candidates(chars, a, b, ct, index, plains,
                                     ciphertexts, src, max_err):
                continue  # a valid word can still fill/correct it
            deads.append((src, a, b))
    return deads


def _retract_weakest(votes, key, known, a, b, blocked):
    """
    Drop the least-supported keystream byte among columns [a, b] and block it, so
    re-convergence must try a different value (which also re-decrypts the shared
    column in the other messages).
    """
    cols = [p for p in range(a, b + 1) if p < len(known) and known[p]]
    if not cols:
        return None
    pos = min(cols, key=lambda p: votes[p].get(key[p], 0))
    blocked.setdefault(pos, set()).add(key[pos])
    votes[pos].pop(key[pos], None)
    if not votes[pos]:
        del votes[pos]  # don't leave an empty Counter behind
    return pos


def _retract_passes(votes, ciphertexts, index, length, committed, blocked,
                    min_votes, fill_w, corr_w, max_err, max_passes, rounds, log):
    """
    Alternate convergence with retraction: find contradictory tokens, remove
    their weakest byte, and re-converge -- letting a different (valid) word win.
    """
    for r in range(rounds):
        key, known, _ = recover_keystream(votes, length, min_votes)
        plains = [_decrypt_chars(ct, key, known) for ct in ciphertexts]
        deads = _dead_end_tokens(plains, ciphertexts, index, max_err)
        if not deads:
            break
        dropped = 0
        for src, a, b in deads:
            if _retract_weakest(votes, key, known, a, b, blocked) is not None:
                dropped += 1
        log(f"  retract round {r + 1}: {len(deads)} dead-end token(s), "
            f"dropped {dropped} byte(s)")
        if not dropped:
            break
        _auto_passes(votes, ciphertexts, index, length, committed, blocked,
                     min_votes, fill_w, corr_w, max_err, max_passes, log)


def iterative_recover(matches, ciphertexts, words, min_votes=2, max_passes=40,
                      fill_weight=4, corr_weight=1000, max_err=1, max_options=8,
                      retract_rounds=8, interactive=False, log=print,
                      prompt=input):
    """
    Reconstruct, then repeatedly complete and correct words until convergence.

    For every message each pass solves space-delimited tokens (fill gaps / fix
    one-letter errors) and extends anchored fragments via prefix/suffix/substring
    candidates, accepting only bytes that stay consistent across all messages.
    Fixing one byte helps every message (shared keystream), so it cascades.

    Convergence alternates with *retraction*: a committed byte that leaves some
    token with no valid word was a mistake, so it is dropped and blocked and the
    region re-solved with a different value.

    With interactive=True, once that settles, any remaining spot where several
    words are *all* cross-message valid is presented for the user to choose; each
    choice re-triggers the automatic cascade.
    """
    length = max((len(ct) for ct in ciphertexts), default=0)
    index = WordIndex(words)
    votes = collect_keystream_votes(matches, ciphertexts)
    committed = set()
    blocked = {}

    _auto_passes(votes, ciphertexts, index, length, committed, blocked,
                 min_votes, fill_weight, corr_weight, max_err, max_passes, log)
    _retract_passes(votes, ciphertexts, index, length, committed, blocked,
                    min_votes, fill_weight, corr_weight, max_err, max_passes,
                    retract_rounds, log)
    if interactive:
        _interactive_loop(votes, ciphertexts, index, length, committed, blocked,
                          min_votes, fill_weight, corr_weight, max_err,
                          max_passes, max_options, log, prompt=prompt)

    key, known, confidence = recover_keystream(votes, length, min_votes)
    plaintexts = decrypt_with_keystream(ciphertexts, key, known)
    conflicts = find_conflicts(votes)
    recovered = sum(known)
    corroborated = sum(1 for pos, c in votes.items()
                       if pos < length and c and c.most_common(1)[0][1] >= 2)
    return {
        "key": key, "known": known, "confidence": confidence,
        "plaintexts": plaintexts, "conflicts": conflicts, "length": length,
        "recovered": recovered, "corroborated": corroborated,
    }
