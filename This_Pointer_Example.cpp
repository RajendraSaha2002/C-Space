#include <iostream>
using namespace std;
class Coordinates
{
    private:
    int latitude;
    int longitude;
    public:
    Coordinates(int lat =0, int lon =0)
    {
        this ->latitude =lat;
        this ->longitude =lon;
    }
    Coordinates& setLatitude(int lat)
    {
        latitude =lat;
        return *this;
    }
    Coordinates& setLongitude(int lon)
    {
        longitude =lon;
        return *this;
    }
    void display() const{
        cout<<"Latitude="<<latitude<<",Longitude="<<longitude<<endl;
    }
};
int main()
{
    Coordinates location(15, 30);
    location.setLatitude(40).setLongitude(70);
    location.display();
    return 0;
}