#include <iostream>
#include <string>
int main(int argc, char* argv[])
{
    std::string gray, binary;
    std::cout<<"Enter the gray code";
    std::cin>>gray;
    binary=gray[0];
    for(int i=0;i<gray.length()-1;i++)
    {
        if(binary[i]==gray[i+1])
        binary=binary + "0";
        else
        {
            binary=binary+"1";

        }
    }
        std::cout<<"Gray Code:"<<gray<<std::endl<<"Binary Code:"<<binary<<std::endl;
        return 0;
    
}