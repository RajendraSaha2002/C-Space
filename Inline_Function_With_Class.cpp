#include <iostream>
using namespace std;
class Number
{
    private:
    int num1;
    int num2;
    public:
    void setValues(int a, int b);
    void printValues();
    inline int addNumbers();
};
void Number::setValues(int a, int b)
{
    num1 =a;
    num2 =b;

}
void Number::printValues()
{
    cout<<"Number 1:"<<num1<<", Number 2:"<<num2<<endl;

}
inline int Number::addNumbers()
{
    return num1 + num2;
}
int main()
{
    Number n;
    n.setValues(10, 20);
    n.printValues();
    int sum =n.addNumbers();
    cout<<"Sum of the numbers:"<<sum<<endl;
    return 0;
}