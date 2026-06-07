#include <iostream>
using namespace std;
class Vehicle 
{
    public:
    virtual void honk() final
    {
        cout<<"Vehicle honk:Beep beep!"<<endl;
    }
};
class SportsCar:public Vehicle{

};
int main()
{
    Vehicle* v =new SportsCar();
    v ->honk();
    return 0;
}