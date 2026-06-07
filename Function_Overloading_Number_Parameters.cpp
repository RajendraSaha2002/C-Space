#include <iostream>
using namespace std;
void display(int a)
{
    cout<<"Display with one integer:"<<a<<endl;

}
void display(int a, double b)
{
    cout<<"Display with an integer and a double:"<<a<<"and"<<b<<endl;
}
int main()
{
    display(10);
    display(10, 3.14);
   
    return 0;

}