#include <iostream>
#include <thread>
void hello()
{
    std::cout<<"I love you Suchismita!"<<std::endl;
}
int main()
{
    std::thread t(hello);
    t.join();
    return 0;
}