#include <iostream>
using namespace std;
class MathOperation
{
    public:
    static int square(int num)
    {
        return num*num;
    }
};
int main()
{
    std::cout<<"Square of 2:"<<MathOperation::square(2)<<'\n';
    return 0;
}