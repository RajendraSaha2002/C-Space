#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    // argc is the number of arguments, including the program name itself.
    // If argc is 1, no additional arguments were supplied.
    if (argc == 1) {
        std::cout << "No command-line arguments were provided." << std::endl;
    } else if (argc == 2) {
        // If there is one argument besides the program name
        std::cout << "One argument was supplied: " << argv[1] << std::endl;
    } else {
        // If there are multiple arguments
        std::cout << "Multiple arguments were supplied." << std::endl;
        std::cout << "They are:" << std::endl;
        // Loop through all arguments, starting from the second one (index 1)
        for (int i = 1; i < argc; ++i) {
            std::cout << i << ": " << argv[i] << std::endl;
        }
    }

    return 0;
}