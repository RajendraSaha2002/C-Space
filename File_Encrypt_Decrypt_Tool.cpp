#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <algorithm>
using namespace std;

class FileEncryptor {
private:
    string key;
    
    // XOR encryption/decryption (symmetric)
    void xorCipher(char* data, int size) {
        int keyLen = key.length();
        for (int i = 0; i < size; i++) {
            data[i] ^= key[i % keyLen];
        }
    }
    
    // Caesar cipher for simple encryption
    void caesarEncrypt(char* data, int size, int shift) {
        for (int i = 0; i < size; i++) {
            if (isalpha(data[i])) {
                char base = isupper(data[i]) ? 'A' : 'a';
                data[i] = ((data[i] - base + shift) % 26) + base;
            }
        }
    }
    
    void caesarDecrypt(char* data, int size, int shift) {
        caesarEncrypt(data, size, 26 - shift);
    }
    
    // Enhanced encryption using multiple passes
    void advancedEncrypt(char* data, int size) {
        // Pass 1: XOR with key
        xorCipher(data, size);
        
        // Pass 2: Byte substitution
        for (int i = 0; i < size; i++) {
            data[i] = ~data[i]; // Bitwise NOT
        }
        
        // Pass 3: Position-based XOR
        for (int i = 0; i < size; i++) {
            data[i] ^= (i % 256);
        }
    }
    
    void advancedDecrypt(char* data, int size) {
        // Reverse order of encryption
        for (int i = 0; i < size; i++) {
            data[i] ^= (i % 256);
        }
        
        for (int i = 0; i < size; i++) {
            data[i] = ~data[i];
        }
        
        xorCipher(data, size);
    }

public:
    FileEncryptor(const string& encKey = "SecretKey123") : key(encKey) {}
    
    void setKey(const string& newKey) {
        if (newKey.empty()) {
            cout << "Key cannot be empty. Using default key.\n";
            return;
        }
        key = newKey;
    }
    
    bool encryptFile(const string& inputFile, const string& outputFile, int method = 1) {
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cout << "Error: Cannot open input file '" << inputFile << "'\n";
            return false;
        }
        
        // Get file size
        inFile.seekg(0, ios::end);
        long fileSize = inFile.tellg();
        inFile.seekg(0, ios::beg);
        
        if (fileSize == 0) {
            cout << "Error: File is empty.\n";
            return false;
        }
        
        // Read file content
        char* buffer = new char[fileSize];
        inFile.read(buffer, fileSize);
        inFile.close();
        
        // Encrypt based on method
        switch(method) {
            case 1: xorCipher(buffer, fileSize); break;
            case 2: caesarEncrypt(buffer, fileSize, 13); break;
            case 3: advancedEncrypt(buffer, fileSize); break;
            default: 
                cout << "Invalid encryption method.\n";
                delete[] buffer;
                return false;
        }
        
        // Write encrypted content
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cout << "Error: Cannot create output file '" << outputFile << "'\n";
            delete[] buffer;
            return false;
        }
        
        outFile.write(buffer, fileSize);
        outFile.close();
        delete[] buffer;
        
        cout << "File encrypted successfully!\n";
        cout << "Input: " << inputFile << " (" << fileSize << " bytes)\n";
        cout << "Output: " << outputFile << "\n";
        return true;
    }
    
    bool decryptFile(const string& inputFile, const string& outputFile, int method = 1) {
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cout << "Error: Cannot open input file '" << inputFile << "'\n";
            return false;
        }
        
        // Get file size
        inFile.seekg(0, ios::end);
        long fileSize = inFile.tellg();
        inFile.seekg(0, ios::beg);
        
        // Read file content
        char* buffer = new char[fileSize];
        inFile.read(buffer, fileSize);
        inFile.close();
        
        // Decrypt based on method
        switch(method) {
            case 1: xorCipher(buffer, fileSize); break;
            case 2: caesarDecrypt(buffer, fileSize, 13); break;
            case 3: advancedDecrypt(buffer, fileSize); break;
            default:
                cout << "Invalid decryption method.\n";
                delete[] buffer;
                return false;
        }
        
        // Write decrypted content
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cout << "Error: Cannot create output file '" << outputFile << "'\n";
            delete[] buffer;
            return false;
        }
        
        outFile.write(buffer, fileSize);
        outFile.close();
        delete[] buffer;
        
        cout << "File decrypted successfully!\n";
        cout << "Input: " << inputFile << " (" << fileSize << " bytes)\n";
        cout << "Output: " << outputFile << "\n";
        return true;
    }
    
    void displayInfo() {
        cout << "\n===== ENCRYPTION METHODS =====\n";
        cout << "1. XOR Cipher (Fast, Good for any file type)\n";
        cout << "2. Caesar Cipher (Text files only)\n";
        cout << "3. Advanced Multi-Pass (Most secure)\n";
        cout << "\nNote: Use the same method and key for decryption!\n";
    }
};

void clearScreen() {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
}

int main() {
    FileEncryptor encryptor;
    string customKey, inputFile, outputFile;
    int choice, method;
    
    cout << "===== FILE ENCRYPTION/DECRYPTION TOOL =====\n\n";
    cout << "Do you want to use a custom encryption key? (y/n): ";
    char useCustom;
    cin >> useCustom;
    
    if (useCustom == 'y' || useCustom == 'Y') {
        cout << "Enter your encryption key: ";
        cin.ignore();
        getline(cin, customKey);
        encryptor.setKey(customKey);
        cout << "Custom key set successfully!\n";
    } else {
        cout << "Using default encryption key.\n";
    }
    
    do {
        cout << "\n===== MAIN MENU =====\n";
        cout << "1. Encrypt a File\n";
        cout << "2. Decrypt a File\n";
        cout << "3. View Encryption Methods\n";
        cout << "4. Change Encryption Key\n";
        cout << "5. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;
        cin.ignore();
        
        switch(choice) {
            case 1:
                encryptor.displayInfo();
                cout << "\nEnter input file path: ";
                getline(cin, inputFile);
                cout << "Enter output file path: ";
                getline(cin, outputFile);
                cout << "Select encryption method (1-3): ";
                cin >> method;
                encryptor.encryptFile(inputFile, outputFile, method);
                break;
                
            case 2:
                encryptor.displayInfo();
                cout << "\nEnter encrypted file path: ";
                getline(cin, inputFile);
                cout << "Enter output file path: ";
                getline(cin, outputFile);
                cout << "Select decryption method (1-3): ";
                cin >> method;
                encryptor.decryptFile(inputFile, outputFile, method);
                break;
                
            case 3:
                encryptor.displayInfo();
                break;
                
            case 4:
                cout << "Enter new encryption key: ";
                getline(cin, customKey);
                encryptor.setKey(customKey);
                cout << "Encryption key updated!\n";
                break;
                
            case 5:
                cout << "\nThank you for using File Encryption Tool!\n";
                break;
                
            default:
                cout << "Invalid choice! Please try again.\n";
        }
    } while(choice != 5);
    
    return 0;
}