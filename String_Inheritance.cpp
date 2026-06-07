#include <bits/stdc++.h>
using namespace std;
class parent
{
  public:virtual string
  concatenate(string s1, string s2)=0;
};
class child:parent
{
  public:
  string concatenate(string s1, string s2)
  {
    s1+=s2;
    return s1;
  }
};
int main()
{
    child ch1;
    cout<<ch1.concatenate("I love you", "Suchismita !!!");
    return 0;
}