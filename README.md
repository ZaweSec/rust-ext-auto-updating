# **Project Name - RUNTIME AUTO UPDATE OFFSETS/DECRYPTION**

## **Preface**  
This project is a proof of concept for dynamically resolving offsets and decrypting data at runtime using **Zydis**, eliminating the need for manual updates.  

Currently, it supports only **BaseNetworkable** offsets/decryption and **MainCamera**.  

### **Note:**  
This project was developed in a single night simply because I was tired of constantly updating decryptions. 😆  

_Company X just lost a lot of money with these encryptions..._  

## **How to use:**  

### **1st - Install Zydis using vcpkg**  

```bash
# Clone vcpkg from the Microsoft repo
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg

# Bootstrap vcpkg
bootstrap-vcpkg.bat

# Integrate vcpkg
vcpkg integrate install

# Install Zydis
vcpkg install zydis
```

### **2nd - Compile the solution** 😏🛠  
