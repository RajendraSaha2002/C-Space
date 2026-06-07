#include <iostream>
#include <string>
using namespace std;

// Base class
class Bank {
protected:
    int accountNumber;
    string customerName;
    float balance;

public:
    // Default constructor
    Bank() {
        accountNumber = 0;
        customerName = "";
        balance = 0.0;
    }
    
    // Method to set basic bank details
    void setDetails() {
        cout << "Enter Account Number: ";
        cin >> accountNumber;
        cin.ignore(); // Clear input buffer
        
        cout << "Enter Customer Name: ";
        getline(cin, customerName);
        
        cout << "Enter Initial Balance: ";
        cin >> balance;
    }
    
    // Method to display common details
    void displayDetails() const {
        cout << "\n----- Account Details -----" << endl;
        cout << "Account Number: " << accountNumber << endl;
        cout << "Customer Name: " << customerName << endl;
        cout << "Balance: $" << balance << endl;
    }
};

// Derived class for Savings Account
class Save : public Bank {
private:
    float interestRate;
    
public:
    // Constructor
    Save() : interestRate(0.0) {}
    
    // Method to set savings account specific details
    void setSavingsDetails() {
        setDetails(); // Call base class method
        cout << "Enter Interest Rate (%): ";
        cin >> interestRate;
    }
    
    // Method to display savings account details
    void displaySavingsDetails() const {
        displayDetails(); // Call base class method
        cout << "Account Type: Savings" << endl;
        cout << "Interest Rate: " << interestRate << "%" << endl;
        cout << "Interest Amount: $" << (balance * interestRate / 100) << endl;
        cout << "------------------------" << endl;
    }
};

// Derived class for Current Account
class Current : public Bank {
private:
    float overdraftLimit;
    
public:
    // Constructor
    Current() : overdraftLimit(0.0) {}
    
    // Method to set current account specific details
    void setCurrentDetails() {
        setDetails(); // Call base class method
        cout << "Enter Overdraft Limit: $";
        cin >> overdraftLimit;
    }
    
    // Method to display current account details
    void displayCurrentDetails() const {
        displayDetails(); // Call base class method
        cout << "Account Type: Current" << endl;
        cout << "Overdraft Limit: $" << overdraftLimit << endl;
        cout << "Available Funds: $" << (balance + overdraftLimit) << endl;
        cout << "------------------------" << endl;
    }
};
int main() {
    // Creating objects of derived classes
    Save savingsAccount;
    Current currentAccount;
    
    cout << "===== BANK ACCOUNT MANAGEMENT SYSTEM =====" << endl;
    
    // Setting and displaying Savings Account details
    cout << "\n----- Enter Savings Account Details -----" << endl;
    savingsAccount.setSavingsDetails();
    
    cout << "\n----- Enter Current Account Details -----" << endl;
    currentAccount.setCurrentDetails();
    
    // Display account information
    cout << "\n===== ACCOUNT INFORMATION =====" << endl;
    
    savingsAccount.displaySavingsDetails();
    currentAccount.displayCurrentDetails();
    
    return 0;
}