#include <bits/stdc++.h>
using namespace std;
class concatenate
{
    public:
   const char s1[26]="I love you Suchismita !!!";
   char s2[20]="Hey...";
    friend void helper(concatenate par1);
};
void helper(concatenate par1)
{
    strcat(par1.s2, par1.s1);
    cout<<par1.s2;
}
int main()
{
    concatenate par1;
    helper(par1);
    return 0;
}
