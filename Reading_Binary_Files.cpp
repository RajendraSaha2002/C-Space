#include <iostream>
#include <fstream>
int main()
{
    std::ifstream file("example.bin", std::ios::binary);
    if(!file)
    {
        std::cerr<<"Error opening file!"<<std::endl;
        return 1;
    }
    file.seekg(0, std::ios::end);
    std::streamsize size=
    file.tellg();
    file.seekg(0, std::ios::beg);
    char*buffer =new char[size];
    file.read(buffer, size);
    for(std::streamsize i=0; i<size; ++i)
    {
        std::cout<<std::hex<<(0xFF & buffer[i])<<"";
    }
    delete[] buffer;
    file.close();
    return 0;
}