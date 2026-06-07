#include <iostream>
using namespace std;
enum class status : unsigned int
{
    Ok=0,
    Error=1,
    Warning=2
};
int main()
{
    status s=status::Error;
    cout<<"The integer value of Error is:"<<static_cast<unsigned int>(s)<<endl;
    return 0;
}