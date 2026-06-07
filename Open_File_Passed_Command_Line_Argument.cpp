#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char* argv[]) {
    // Check if a filename was provided as an argument
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1; // Exit with an error code
    }

    // The first argument (argv[0]) is the program name,
    // so the filename is the second argument (argv[1]).
    std::string filename = argv[1];

    // Create an input file stream object
    std::ifstream inputFile(filename);

    // Check if the file was successfully opened
    if (!inputFile.is_open()) {
        std::cerr << "Error: Could not open the file '" << filename << "'." << std::endl;
        return 1; // Exit with an error code
    }

    std::cout << "Successfully opened the file: " << filename << std::endl;
    std::cout << "--- File Content ---" << std::endl;
    
    // Read and print the content of the file line by line
    std::string line;
    while (std::getline(inputFile, line)) {
        std::cout << line << std::endl;
    }

    // Close the file stream
    inputFile.close();

    return 0; // Exit successfully
}