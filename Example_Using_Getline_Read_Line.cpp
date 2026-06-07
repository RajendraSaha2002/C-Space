#include <fstream>
#include <iostream>
#include <string>
int main()
{
    std::ifstream
    inputfile("example.txt");
    if(!inputfile)
    {
        std::cerr<<"Error opening file!"<<std::endl;
        return 1;
    }
    std::string line;
    while(std::getline(inputfile, line))
    {
        std::cout<<line<<std::endl;
    }
    inputfile.close();
    return 0;
}