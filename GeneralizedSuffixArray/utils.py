import pickle


def save_suffix_array(suffix_array, word_list, file_path):
    """
    Save the suffix array and word list to a file.

    Args:
        suffix_array (list): The suffix array as a list of tuples.
        word_list (list): The list of words corresponding to the suffix array.
        file_path (str): The file path to save the data.
    """
    with open(file_path, 'wb') as file:
        pickle.dump({'suffix_array': suffix_array,
                    'word_list': word_list}, file)


def load_suffix_array(file_path):
    """
    Load the suffix array and word list from a file.

    Args:
        file_path (str): The file path to load the data from.

    Returns:
        tuple: A tuple (suffix_array, word_list).
    """
    with open(file_path, 'rb') as file:
        data = pickle.load(file)
    return data['suffix_array'], data['word_list']
