#include <iostream>
using namespace std;
class numbers
{
    private:
    int a;
    int b;
    public:
    void setValues(int x, int y)
    {
        a = x;
        b = y;
    }
    double addition()
    {
        return a + b;
    }
    void display()
    {
        cout<<"a:"<<a<<", b:"<<b<<endl;
    }

};
int main()
{
    numbers num;
    num.setValues(10, 20);
    num.display();
    int sum = num.addition();
    cout<<"Sum of numbers:"<<sum<<endl;
    return 0;

}