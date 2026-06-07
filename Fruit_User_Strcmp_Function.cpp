#include <iostream>
#include <cstring>

int main() {
    char answer[50];

    std::cout << "What is your favourite fruit? ";
    std::cin.getline(answer, 50);

    if (strcmp(answer, "mango") == 0) {
        std::cout << "The answer is right." << std::endl;
    } else {
        std::cout << "The answer is wrong." << std::endl;
    }

    return 0;
}