#include <iostream>
#include <string>
#include <vector>

#include "../lib/json.hpp"
#include "SfxTrie.h"

using json = nlohmann::json;

int main() {
  // Load the suffix trie once
  SfxTrie trie("dictionary/english-words.all");
  std::cerr << "Trie loaded. Waiting for commands...\n";

  std::string line;
  while (std::getline(std::cin, line)) {
    try {
      // Parse input JSON
      json input = json::parse(line);
      std::string command = input["command"];
      std::string suffix = input["suffix"];
      json output;

      if (command == "search") {
        // Execute search
        std::vector<int> results = trie.search(suffix);
        output = results;  // Convert vector to JSON array
      } else if (command == "count") {
        // Execute countWordsWithSuffix
        int count = trie.countWordsWithSuffix(suffix);
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
