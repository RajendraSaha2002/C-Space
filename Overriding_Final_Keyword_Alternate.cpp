#include <iostream>
using namespace std;
class Subject
{
    public:
    virtual void examType() final
    {
        cout<<"This subject has a written exam."<<endl;
    }
};
class Math:public Subject
{
  
};
int main()
{
    Subject* s = new Math();
    s ->examType();
    delete s;
    return 0;
}
