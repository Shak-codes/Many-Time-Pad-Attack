#include <iostream>
#include <string>
#include <vector>

#include "../lib/json.hpp"
#include "WordTrie.h"

using json = nlohmann::json;

int main() {
  // Load the suffix trie once
  WordTrie trie("dictionary/english-words.all");
  std::cerr << "Trie loaded. Waiting for commands...\n";

  std::string line;
  while (std::getline(std::cin, line)) {
    try {
      // Parse input JSON
      json input = json::parse(line);
      std::string command = input["command"];
      std::string type = input["type"];
      std::string string = input["string"];
      json output;

      if (command == "search" && type == "prefix") {
        std::vector<int> results = trie.searchPrefix(string);
        output = results;
      } else if (command == "search" && type == "suffix") {
        std::vector<int> results = trie.searchSuffix(string);
        output = results;
      } else if (command == "count" && type == "prefix") {
        int count = trie.countWordsWithPrefix(string);
        output = {{"count", count}};
      } else if (command == "count" && type == "suffix") {
        int count = trie.countWordsWithSuffix(string);
        output = {{"count", count}};
      } else {
        output = {{"error", "Invalid command"}};
      }

      // Output JSON response
      std::cout << output.dump() << std::endl;
    } catch (const std::exception& e) {
      // Handle errors gracefully
      std::cerr << "Error: " << e.what() << std::endl;
      std::cout << json({{"error", "Invalid input"}}).dump() << std::endl;
    }
  }

  std::cerr << "Shutting down...\n";
  return 0;
}
