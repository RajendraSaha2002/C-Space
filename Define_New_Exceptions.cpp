#include <iostream>
#include <exception>
using namespace std;
struct MyException: public exception
{
    const char*what()const throw()
    {
        return "Suchismita Saha";
    }
};
int main()
{
    try
    {
        throw MyException();
    }
    catch(MyException& e)
    {
        std::cout<<"I Love You Suchismita Saha"<<std::endl;
        std::cout<<e.what()<<std::endl;
    }
    catch(std::exception& e)
    {

    }
}