#include <iostream>
using namespace std;
enum day
{
    Sunday,
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday=45,
    Saturday,
};
int main()
{
    day get1=Wednesday;
    cout<<get1<<endl;
    cout<<Saturday<<endl;
    return 0;
}