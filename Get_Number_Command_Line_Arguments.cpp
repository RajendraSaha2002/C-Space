#include <iostream>

int main(int argc, char* argv[]) {
    // argc holds the total number of arguments, including the program name.
    std::cout << "The total number of command-line arguments is: " << argc << std::endl;
    
    // Display the arguments themselves for clarity.
    for (int i = 0; i < argc; ++i) {
        std::cout << "Argument " << i << ": " << argv[i] << std::endl;
    }

    return 0;
}