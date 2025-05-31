#include "WordTrie.h"

#include <fstream>
#include <iostream>

Node::~Node() {
  for (auto& [key, child] : children) {
    delete child;  // Recursively delete child nodes
  }
}

WordTrie::WordTrie(const std::string& file_path) {
  prefix_root = new Node();
  suffix_root = new Node();

  // Open the file
  std::ifstream file(file_path);
  if (!file.is_open()) {
    std::cerr << "Error: Could not open file " << file_path << std::endl;
    exit(EXIT_FAILURE);
  }

  // Read words from the file
  std::string word;
  int word_index = 0;
  while (std::getline(file, word)) {
    if (!word.empty()) {
      word.erase(0, word.find_first_not_of(" \t\n\r\f\v"));  // Leading
      word.erase(word.find_last_not_of(" \t\n\r\f\v") + 1);  // Trailing
      str_arr.push_back(word);  // Add the word to the instance's array
      insert(word_index++);     // Insert its suffixes into the trie
    }
  }

  file.close();
  std::cout << "Loaded " << str_arr.size() << " words from " << file_path
            << std::endl;
}

WordTrie::~WordTrie() {
  delete prefix_root;
  delete suffix_root;
}

void WordTrie::insert(int word_index) {
  const std::string& word = str_arr[word_index];  // Get the word from str_arr

  // Inserting into Suffix Trie
  for (size_t i = 0; i < word.size(); ++i) {
    Node* current = suffix_root;

    // Traverse and insert each character of the suffix
    for (size_t j = i; j < word.size(); ++j) {
      char c = word[j];
      if (current->children.find(c) == current->children.end()) {
        current->children[c] = new Node();
      }
      current = current->children[c];

      // Add the word index to the word_indices array for the current node
      current->word_indices.push_back(word_index);

      // Avoid duplicate indices in word_indices
      if (current->word_indices.size() > 1 &&
          current->word_indices[current->word_indices.size() - 1] ==
              current->word_indices[current->word_indices.size() - 2]) {
        current->word_indices.pop_back();
      }

      // Increment count of words with this suffix
      current->words_count++;
    }
  }

  // Inserting into Prefix Trie
  Node* current_prefix = prefix_root;
  for (size_t i = 0; i < word.size(); ++i) {
    char c = word[i];
    if (current_prefix->children.find(c) == current_prefix->children.end()) {
      current_prefix->children[c] = new Node();
    }
    current_prefix = current_prefix->children[c];

    // Add the word index and avoid duplicate indices in the prefix trie
    current_prefix->word_indices.push_back(word_index);
    if (current_prefix->word_indices.size() > 1 &&
        current_prefix->word_indices[current_prefix->word_indices.size() - 1] ==
            current_prefix
                ->word_indices[current_prefix->word_indices.size() - 2]) {
      current_prefix->word_indices.pop_back();
    }
    // Increment count for words with this prefix
    current_prefix->words_count++;
  }
}

std::vector<int> WordTrie::searchSuffix(const std::string& suffix) const {
  Node* current = suffix_root;  // Start at the root of the suffix trie

  // Traverse the trie character by character
  for (char c : suffix) {
    if (current->children.find(c) == current->children.end()) {
      // If the character is not found, the suffix does not exist
      return {};
    }
    current = current->children[c];
  }

  // If we reach the end of the suffix, return the list of word indices
  return current->word_indices;
}

std::vector<int> WordTrie::searchPrefix(const std::string& prefix) const {
  Node* current = prefix_root;  // Start at the root of the prefix trie

  // Traverse the trie character by character
  for (char c : prefix) {
    if (current->children.find(c) == current->children.end()) {
      // If the character is not found, the prefix does not exist
      return {};
    }
    current = current->children[c];
  }

  // If we reach the end of the prefix, return the list of word indices
  return current->word_indices;
}

const std::vector<std::string>& WordTrie::getStrArr() const { return str_arr; }

int WordTrie::countWordsWithSuffix(const std::string& suffix) const {
  Node* current = suffix_root;

  // Traverse the trie following the characters of the suffix
  for (char c : suffix) {
    if (current->children.find(c) == current->children.end()) {
      return 0;  // Suffix not found
    }
    current = current->children[c];
  }

  // Return the count of words with this suffix
  return current->words_count;
}

int WordTrie::countWordsWithPrefix(const std::string& prefix) const {
  Node* current = prefix_root;  // Start at the root of the prefix trie

  // Traverse the trie following the characters of the prefix
  for (char c : prefix) {
    if (current->children.find(c) == current->children.end()) {
      return 0;  // Prefix not found
    }
    current = current->children[c];
  }

  // Return the count of words with this prefix
  return current->words_count;
}
