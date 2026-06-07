#include <iostream>
using namespace std;
class Base1
{
    public:
    void show()
    {
        cout<<"Base1 show"<<endl;
    }
};
class Base2
{
    public:
    void show()
    {
        cout<<"Base2 show"<<endl;
    }
};
class Derived: public Base1, public Base2
{
    public:
    void show()
    {
        Base1 ::show();
        Base2 ::show();
    }
};
int main()
{
    Derived obj;
    obj.show();
    return 0;
}