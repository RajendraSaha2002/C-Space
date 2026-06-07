#include <fstream>
#include <iostream>
#include <string>
#include <direct.h>   // _getcwd
#include <limits.h>   // _MAX_PATH

int main(int argc, char* argv[])
{
    // Use file path from command line if provided, else default to example.txt
    std::string path = (argc > 1) ? argv[1] : std::string("example.txt");

    std::ifstream inputfile(path);
    if (!inputfile)
    {
        std::cerr << "Error opening file: " << path << std::endl;

        // Help diagnose by showing the current working directory
        char cwd[_MAX_PATH];
        if (_getcwd(cwd, _MAX_PATH))
        {
            std::cerr << "Current working directory: " << cwd << std::endl;
            std::cerr << "Place the file here, or provide a full path." << std::endl;
        }
        else
        {
            std::cerr << "(Could not determine current working directory)" << std::endl;
        }

        // Let the user provide a full path interactively
        std::cerr << "Enter full path to the input file (or press Enter to exit): ";
        std::string manualPath;
        std::getline(std::cin, manualPath);
        if (manualPath.empty())
            return 1;

        inputfile.clear();
        inputfile.open(manualPath);
        if (!inputfile)
        {
            std::cerr << "Still cannot open: " << manualPath << std::endl;
            return 1;
        }
    }

    // Read words using the stream extraction operator (>>) and print them
    std::string word;
    while (inputfile >> word)
    {
        std::cout << word << std::endl;
    }

    inputfile.close();
    return 0;
}