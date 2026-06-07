#include <iostream>
using namespace std;
class Car
{
    public:
    void drive()
    {
        cout<<"Driving on land"<<endl;
    }
};
class Boat
{
    public:
    void sail()
    {
        cout<<"Sailing on water"<<endl;
    }
};
class DualModeVehicle: public Car, public Boat{
    public:
    void use()
    {
        drive();
        sail();
    }
};
int main()
{
    DualModeVehicle myVehicle;
    myVehicle.use();
    return 0;
}