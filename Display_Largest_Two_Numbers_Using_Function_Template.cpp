#include <iostream>
#include <string>

// Function template to find the largest of two numbers
template <typename T>
T findMax(T a, T b) {
    return (a > b) ? a : b;
}

int main() {
    // Example with integers
    int maxInt = findMax(15, 7);
    std::cout << "The largest integer is: " << maxInt << std::endl;

    // Example with characters
    char maxChar = findMax('c', 'a');
    std::cout << "The largest character is: " << maxChar << std::endl;
    
    // Example with floating-point numbers
    float maxFloat = findMax(3.14f, 2.71f);
    std::cout << "The largest float is: " << maxFloat << std::endl;
    
    // Example with strings
    std::string maxString = findMax(std::string("hello"), std::string("world"));
    std::cout << "The largest string (lexicographically) is: " << maxString << std::endl;

    return 0;
}