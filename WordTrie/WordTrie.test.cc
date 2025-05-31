#include "WordTrie.h"

#include <cassert>
#include <iostream>

// Function to run all tests
void runTests() {
  std::cout << "Running SfxTrie Tests...\n";

  // Test 1: Constructor and file loading
  std::cout << "Test 1: Constructor and file loading\n";
  WordTrie trie("../dictionary/english-words.all");
  const auto& str_arr = trie.getStrArr();  // Call on the instance
  assert(!str_arr.empty() &&
         "The word array should not be empty after loading the file.");
  std::cout << "Loaded " << str_arr.size() << " words successfully.\n";

  // Test 2: Insertion and search for existing suffix
  std::cout << "Test 2: Search for an existing suffix\n";
  std::string suffix1 = "ever";
  std::vector<int> results1 = trie.searchSuffix(suffix1);
  if (!results1.empty()) {
    std::cout << "Suffix '" << suffix1 << "' found in the following words:\n";
    for (int index : results1) {
      std::cout << "- " << str_arr[index] << "\n";
    }
  } else {
    std::cout << "Suffix '" << suffix1 << "' not found.\n";
  }

  // Test 3: Search for a non-existent suffix
  std::cout << "Test 3: Search for a non-existent suffix\n";
  std::string suffix2 = "xyz";
  std::vector<int> results2 = trie.searchSuffix(suffix2);
  assert(results2.empty() && "The suffix 'xyz' should not exist in the trie.");
  std::cout << "Suffix '" << suffix2 << "' not found as expected.\n";

  // Test 4: Edge case - Search for a single character suffix
  std::cout << "Test 4: Search for a single character suffix\n";
  std::string suffix3 = "z";
  std::vector<int> results3 = trie.searchSuffix(suffix3);
  if (!results3.empty()) {
    std::cout << "Suffix '" << suffix3 << "' found in the following words:\n";
    for (int index : results3) {
      std::cout << "- " << str_arr[index] << "\n";
    }
  } else {
    std::cout << "Suffix '" << suffix3 << "' not found.\n";
  }

  // Test 5: Edge case - Search for the entire word as a suffix
  std::cout << "Test 5: Search for an entire word as a suffix\n";
  if (!str_arr.empty()) {
    std::string suffix4 =
        str_arr[22643];  // Use the first word in the array as the suffix
    std::vector<int> results4 = trie.searchSuffix(suffix4);
    assert(!results4.empty() && "The entire word as a suffix should exist.");
    std::cout << "Suffix '" << suffix4 << "' found in the following words :\n ";
    for (int index : results4) {
      std::cout << "- " << str_arr[index] << "\n";
    }
  } else {
    std::cout << "The word array is empty. Test 5 skipped.\n";
  }

  // Test 6: Count words with a specific suffix
  std::cout << "Test 3: Count words with the suffix 'everl'\n";
  std::string suffix5 = "everl";
  int count = trie.countWordsWithSuffix(suffix5);
  std::cout << "Number of words containing the suffix '" << suffix5
            << "': " << count << "\n";
  assert(count > 0 &&
         "The suffix 'everl' should be found in at least one word.");

  // Test 7: Count words with a specific suffix that doesn't exist
  std::cout << "Test 3: Count words with the suffix 'everl'\n";
  std::string suffix6 = "everlxx";
  int count2 = trie.countWordsWithSuffix(suffix6);
  std::cout << "Number of words containing the suffix '" << suffix6
            << "': " << count2 << "\n";
  assert(count2 == 0 && "The suffix 'everlxx' should not be found at all.");

  std::cout << "All tests completed successfully.\n";

  // Test 8: Search for existing prefix
  std::cout << "Test 8: Search for an existing prefix\n";
  std::string prefix1 = "ever";
  std::vector<int> results4 = trie.searchPrefix(prefix1);
  if (!results1.empty()) {
    std::cout << "Prefix '" << prefix1 << "' found in the following words:\n";
    for (int index : results4) {
      std::cout << "- " << str_arr[index] << "\n";
    }
  } else {
    std::cout << "Suffix '" << prefix1 << "' not found.\n";
  }

  // Test 9: Search for a non-existent prefix
  std::cout << "Test 9: Search for a non-existent prefix\n";
  std::string prefix2 = "xyz";
  std::vector<int> results5 = trie.searchPrefix(prefix2);
  assert(results5.empty() && "The prefix 'xyz' should not exist in the trie.");
  std::cout << "Prefix '" << prefix2 << "' not found as expected.\n";

  // Test 10: Edge case - Search for a single character prefix
  std::cout << "Test 10: Search for a single character prefix\n";
  std::string prefix3 = "x";
  std::vector<int> results6 = trie.searchPrefix(prefix3);
  if (!results3.empty()) {
    std::cout << "Prefix '" << prefix3 << "' found in the following words:\n";
    for (int index : results6) {
      std::cout << "- " << str_arr[index] << "\n";
    }
  } else {
    std::cout << "Prefix '" << prefix3 << "' not found.\n";
  }
}

int main() {
  runTests();
  return 0;
}
