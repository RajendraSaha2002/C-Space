#include <iostream>
using namespace std;
class Base
{
    public:
    void show()
    {
        cout<<"Base show"<<endl;
    }
};
class Derived1: virtual public Base {};
class Derived2: virtual public Base {};
class final: public Derived1, public Derived2 {};
int main()
{
    final obj;
    obj.show();
    return 0;
}