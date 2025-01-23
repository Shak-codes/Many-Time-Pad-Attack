#ifndef SFXTRIE_H
#define SFXTRIE_H

#include <string>
#include <unordered_map>
#include <vector>

// Node structure for the suffix trie
struct Node {
  std::unordered_map<char, Node*> children;  // Map of child nodes
  std::vector<int>
      word_indices;           // List of indices of words containing this suffix
  int words_with_suffix = 0;  // Number of words containing this suffix

  Node() = default;
  ~Node();  // Destructor to recursively delete child nodes
};

// SfxTrie class
class SfxTrie {
 private:
  Node* root;  // Root node of the trie
  std::vector<std::string>
      str_arr;  // Global array of words (shared across instances)

 public:
  SfxTrie(const std::string& file_path);  // Constructor to load words from a
                                          // file and build the trie
  ~SfxTrie();                             // Destructor
  void insert(int word_index);  // Insert all suffixes of a word into the trie
  std::vector<int> search(const std::string& suffix)
      const;  // Search for a suffix and get word indices
  int countWordsWithSuffix(const std::string& suffix)
      const;  // Get the number of words with a suffix
  const std::vector<std::string>& getStrArr() const;
};

#endif  // SFXTRIE_H
