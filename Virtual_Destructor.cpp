#include <iostream>
using namespace std;
class BaseClass
{
    public:
    virtual ~BaseClass()
    {
        cout<<"BaseClass Destructor"<<endl;
    }
};
class DerivedClass:public BaseClass
{
    public:
    ~DerivedClass() override
    {
        cout<<"DerivedClass Destructor"<<endl;
    }
};
int main()
{
    BaseClass* a = new DerivedClass();
    delete a;
    return 0;
}