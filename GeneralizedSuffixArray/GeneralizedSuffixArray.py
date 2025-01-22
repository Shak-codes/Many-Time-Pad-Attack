class GeneralizedSuffixArray:
    def __init__(self, word_set):
        """
        Build a generalized suffix array from a set of words.

        Args:
            word_set (set): A set of unique words to build the suffix array.
        """
        self.words = list(word_set)  # Convert set to a consistent list
        self.suffix_array = []
        self._build_suffix_array()

    def _build_suffix_array(self):
        """
        Construct the suffix array and map suffix indices to their words.
        """
        separator = "\0"  # Unique separator to distinguish words
        combined_words = separator.join(self.words) + separator

        # Create all suffixes with their starting indices and word indices
        suffixes = []
        word_start_indices = []
        current_index = 0

        for word_idx, word in enumerate(self.words):
            word_start_indices.append(current_index)
            current_index += len(word) + 1

        for word_idx, start_idx in enumerate(word_start_indices):
            for i in range(len(self.words[word_idx])):
                suffixes.append(
                    (combined_words[start_idx + i:], start_idx + i, word_idx))

        # Sort suffixes lexicographically
        suffixes.sort()
        # Store (suffix start index, word index)
        self.suffix_array = [(s[1], s[2]) for s in suffixes]

    def _binary_search(self, substring):
        """
        Perform binary search to find all matches for a substring.

        Args:
            substring (str): The substring to search for.

        Returns:
            list: A list of indices in the suffix array where the substring matches.
        """
        l, r = 0, len(self.suffix_array) - 1
        matches = []

        while l <= r:
            mid = (l + r) // 2
            suffix_start, word_idx = self.suffix_array[mid]
            word = self.words[word_idx]
            suffix = word[suffix_start -
                          sum(len(w) + 1 for w in self.words[:word_idx]):]

            if suffix.startswith(substring):
                matches.append(mid)

                # Expand to find all matches
                # Look left
                left = mid - 1
                while left >= 0:
                    left_suffix_start, left_word_idx = self.suffix_array[left]
                    left_word = self.words[left_word_idx]
                    left_suffix = left_word[left_suffix_start -
                                            sum(len(w) + 1 for w in self.words[:left_word_idx]):]
                    if left_suffix.startswith(substring):
                        matches.append(left)
                        left -= 1
                    else:
                        break

                # Look right
                right = mid + 1
                while right < len(self.suffix_array):
                    right_suffix_start, right_word_idx = self.suffix_array[right]
                    right_word = self.words[right_word_idx]
                    right_suffix = right_word[right_suffix_start - sum(
                        len(w) + 1 for w in self.words[:right_suffix_start]):]
                    if right_suffix.startswith(substring):
                        matches.append(right)
                        right += 1
                    else:
                        break

                break  # Stop the binary search once matches are found

            elif substring < suffix:
                r = mid - 1
            else:
                l = mid + 1

        return matches

    def find_substring(self, substring):
        """
        Find all words containing the given substring.

        Args:
            substring (str): The substring to search for.

        Returns:
            list: A list of unique words containing the substring.
        """
        matches = self._binary_search(substring)
        word_indices = {self.suffix_array[m][1] for m in matches}
        return [self.words[idx] for idx in word_indices]

    def substring_exists(self, substring):
        """
        Check if at least one word in the suffix array contains the given substring.

        Args:
            substring (str): The substring to search for.

        Returns:
            bool: True if at least one word contains the substring, False otherwise.
        """
        substring = substring.decode(
            'utf-8', errors='ignore')
        left, right = 0, len(self.suffix_array) - 1

        while left <= right:
            mid = (left + right) // 2
            suffix_start, word_idx = self.suffix_array[mid]
            word = self.words[word_idx]
            suffix = word[suffix_start:]

            # Ensure suffix and substring are both strings
            if isinstance(suffix, bytes):
                suffix = suffix.decode("utf-8")  # Decode bytes to string
            if isinstance(substring, bytes):
                # Decode substring if it's in bytes
                substring = substring.decode("utf-8")

            if suffix.startswith(substring):
                # Found a match, return True immediately
                return True
            elif substring < suffix:
                right = mid - 1
            else:
                left = mid + 1

        # No match found
        return False
