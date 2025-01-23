#include <iostream>
#include <nlohmann/json.hpp>  // JSON library (https://github.com/nlohmann/json)
#include <string>
#include <vector>

#include "SfxTrie.h"

using json = nlohmann::json;

int main(int argc, char* argv[]) {
  if (argc < 3) {
    std::cerr << "Usage: ./sfxtrie <file_path> <command> [suffix]" << std::endl;
    return 1;
  }

  std::string file_path = argv[1];  // Path to the word file
  std::string command = argv[2];    // Command: "search" or "count"
  std::string suffix;

  if (command == "search" || command == "count") {
    if (argc < 4) {
      std::cerr << "Suffix is required for 'search' or 'count' command."
                << std::endl;
      return 1;
    }
    suffix = argv[3];
  }

  // Load the suffix trie
  SfxTrie trie("../dictionary/english-words.all");

  if (command == "search") {
    // Execute search and output the results as a JSON array
    std::vector<int> results = trie.search(suffix);
    json output = results;  // Convert vector to JSON array
    std::cout << output.dump() << std::endl;
  } else if (command == "count") {
    // Execute countWordsWithSuffix and output the result as JSON
    int count = trie.countWordsWithSuffix(suffix);
    json output = {{"count", count}};
    std::cout << output.dump() << std::endl;
  } else {
    std::cerr << "Invalid command. Use 'search' or 'count'." << std::endl;
    return 1;
  }

  return 0;
}
