#include <iostream>
using namespace std;
int addition(int a, int b)
{
    return a + b;

}
int addition(int a, int b, int c)
{
    return a+b+c;
}
float addition(float a, float b)
{
    return a + b;
}
int main()
{
    cout<<addition(10.5f, 20.3f)<<endl;
    cout<<addition(10, 20, 30)<<endl;
    cout<<addition(10, 20)<<endl;
    return 0;
}