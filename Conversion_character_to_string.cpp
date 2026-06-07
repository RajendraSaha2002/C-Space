#include <iostream>
#include <string>

int main() {
    // Character to be converted
    char character = 'A';

    // Convert character to string
    std::string str(1, character);

    // Output the result
    std::cout << "The character '" << character << "' as a string is: " << str << std::endl;

    return 0;
}