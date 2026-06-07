#include <iostream>
template<typename T>
void printValue(T value)
{
    std::cout<<value<<std::endl;
}
int main()
{
    printValue(42);
    printValue("Hello");
    printValue(3.14159);
    return 0;
}