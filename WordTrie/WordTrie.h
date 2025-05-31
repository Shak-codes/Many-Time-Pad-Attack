#ifndef WORDTRIE_H
#define WORDTRIE_H

#include <string>
#include <unordered_map>
#include <vector>

struct Node {
  std::unordered_map<char, Node*> children;  // Map of child nodes
  std::vector<int>
      word_indices;  // List of indices of words containing this prefix/suffix
  int words_count = 0;  // Number of words containing this prefix/suffix

  Node() = default;
  ~Node();
};

class WordTrie {
 private:
  Node* prefix_root;
  Node* suffix_root;
  std::vector<std::string> str_arr;  // Global array of words

 public:
  WordTrie(const std::string& file_path);
  ~WordTrie();

  void insert(int word_index);  // Insert the word into both tries

  std::vector<int> searchPrefix(const std::string& prefix) const;
  std::vector<int> searchSuffix(const std::string& suffix) const;

  int countWordsWithPrefix(const std::string& prefix) const;
  int countWordsWithSuffix(const std::string& suffix) const;

  const std::vector<std::string>& getStrArr() const;
};

#endif
