#include <iostream>
using namespace std;
void getDetails(int age, double height, const string& name)
{
    cout<<"Name:"<<name<<",Age:"<<age<<",Height:"<<height<<endl;
}
int main()
{
    getDetails(23, 5.6, "Rajendra");
    return 0;

}

