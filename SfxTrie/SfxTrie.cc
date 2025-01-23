#include "SfxTrie.h"

#include <fstream>
#include <iostream>

Node::~Node() {
  for (auto& [key, child] : children) {
    delete child;  // Recursively delete child nodes
  }
}

SfxTrie::SfxTrie(const std::string& file_path) {
  root = new Node();  // Initialize the root node

  // Open the file
  std::ifstream file(file_path);
  if (!file.is_open()) {
    std::cerr << "Error: Could not open file " << file_path << std::endl;
    exit(EXIT_FAILURE);
  }

  // Read words from the file, one per line
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

SfxTrie::~SfxTrie() {
  delete root;  // Recursively delete all nodes starting from the root
}

void SfxTrie::insert(int word_index) {
  const std::string& word = str_arr[word_index];  // Get the word from str_arr

  // Iterate over all suffixes of the word
  for (size_t i = 0; i < word.size(); ++i) {
    Node* current = root;

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
      current->words_with_suffix++;
    }
  }
}

std::vector<int> SfxTrie::search(const std::string& suffix) const {
  Node* current = root;  // Start at the root of the trie

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

const std::vector<std::string>& SfxTrie::getStrArr() const { return str_arr; }

int SfxTrie::countWordsWithSuffix(const std::string& suffix) const {
  Node* current = root;

  // Traverse the trie following the characters of the suffix
  for (char c : suffix) {
    if (current->children.find(c) == current->children.end()) {
      return 0;  // Suffix not found
    }
    current = current->children[c];
  }

  // Return the count of words with this suffix
  return current->words_with_suffix;
}
