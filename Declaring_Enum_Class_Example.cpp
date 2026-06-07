#include <iostream>
using namespace std;
enum class Day
{
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday
};
int main()
{
    Day today=Day::Friday;
    if(today==Day::Friday)
    {
        cout<<"Today is Friday!"<<endl;
    }
    return 0;
}
