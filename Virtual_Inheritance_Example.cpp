#include <iostream>
using namespace std;
class Base
{
    public:
    void present()
    {
        cout<<"Display from Base class"<<endl;
    }
};
class A: virtual public Base{};
class B: virtual public Base{};
class Final: public A, public B{
    public:
    void get()
    {
        cout<<"Display from Final class"<<endl;
    }
};
int main()
{
    Final obj;
    obj.present();
    obj.get();
    return 0;
}
