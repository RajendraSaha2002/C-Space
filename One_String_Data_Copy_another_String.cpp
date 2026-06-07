#include <iostream>
#include <cstring>

int main() {
    char source[100], destination[100];

    std::cout << "Enter a string: ";
    std::cin.getline(source, 100);

    // Copy source to destination
    strcpy(destination, source);

    std::cout << "Copied string: " << destination << std::endl;

    return 0;
}