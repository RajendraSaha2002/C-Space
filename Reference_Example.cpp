#include <iostream>
using namespace std;
int main()
{
    int c=11;
    int& refer=c;
    cout<<"Initially value of integer is:"<<c<<endl;
    refer=121;
    cout<<"After changing value using refer variable:"<<c<<endl;
    return 0;
}