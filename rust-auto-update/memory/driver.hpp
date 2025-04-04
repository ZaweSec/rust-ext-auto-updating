#pragma once

class Driver {
private:
    HANDLE hProcess;
    std::string processName;
    int processId;

    DWORD GetProcessIdByName(LPCTSTR ProcessName) {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, ProcessName)) {
                    DWORD processId = pt.th32ProcessID;
                    CloseHandle(hsnap);
                    return processId;
                }
            } while (Process32Next(hsnap, &pt));
        }
        CloseHandle(hsnap);
        return 0;
    }

    BYTE* GetModuleBaseAddress(LPCSTR szProcessName, LPCSTR szModuleName) {
        HANDLE hSnap;
        HANDLE procSnap;
        PROCESSENTRY32 pe32;
        int PID;
        MODULEENTRY32 xModule;

        procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (procSnap == INVALID_HANDLE_VALUE) {
            printf("Create Snapshot error\n");
            return 0;
        }
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(procSnap, &pe32) == 0) {
            printf("Process32First error\n");
            CloseHandle(procSnap);
            return 0;
        }

        // Loop through processes until we find szProcessName
        do {
            if (_strcmpi(pe32.szExeFile, szProcessName) == 0) {
                PID = pe32.th32ProcessID;
                hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID); //

                if (hSnap == INVALID_HANDLE_VALUE) {
                    return 0;
                }
                xModule.dwSize = sizeof(MODULEENTRY32);
                if (Module32First(hSnap, &xModule) == 0) {
                    CloseHandle(hSnap);
                    return 0;
                }
                // Loop through modules until we find szModuleName
                do {
                    if (_strcmpi(xModule.szModule, szModuleName) == 0) {
                        CloseHandle(hSnap);
                        return xModule.modBaseAddr;
                    }
                } while (Module32Next(hSnap, &xModule));
                CloseHandle(hSnap);
                return 0;
            }
        } while (Process32Next(procSnap, &pe32));
        CloseHandle(procSnap);
        return 0;
    }

public:
    bool init(std::string ProcessName) {
        processName = ProcessName;
        printf("Waiting %s...\n", ProcessName);
        
        while (!processId) {
            processId = GetProcessIdByName(ProcessName.c_str());
        }

        hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);

        if (!hProcess)
            return false;

        system("cls");
        printf("Found %s\n", ProcessName);
        return true;
    }

    uintptr_t GetModuleBase(std::string modName) {
        return (uintptr_t)GetModuleBaseAddress(processName.c_str(), modName.c_str());
    }

    template <typename T>
    T read(uintptr_t Addr) {
        T value = { };
        SIZE_T bytes;

        if (ReadProcessMemory(hProcess, (LPCVOID)Addr, &value, sizeof(value), &bytes)) {
            return value;
        }

        return value;
    }
    
    template <typename T>
    inline T read_chain( std::uint64_t address , std::vector<std::uint64_t> chain )
    {
        uint64_t cur_read = address;

        for ( size_t r = 0; r < chain.size( ) - 1; ++r ) {
            if ( !cur_read )
                return {};
            cur_read = read<std::uint64_t>( cur_read + chain[ r ] );
        }

        if ( !cur_read )
            return {};

        return read<T>( cur_read + chain[ chain.size( ) - 1 ] );
    }

    inline bool read(PVOID address, PVOID buffer, DWORD size)
    {
        SIZE_T bytes;
        return ReadProcessMemory(hProcess, (LPCVOID)address, address, size, &bytes) ? 1 : 0;
    }

    template <typename T>
    bool write(uintptr_t Addr, const T& value) {
        SIZE_T bytes;

        if (WriteProcessMemory(hProcess, (LPVOID)Addr, &value, sizeof(value), &bytes)) {
            return bytes == sizeof(value);
        }

        return false;
    }
};
inline Driver* driver = nullptr;

uintptr_t PatternScan(void* module, const char* signature, const char* sectionName = nullptr, int skip = 0)
{
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
        };

    auto dosHeader = (PIMAGE_DOS_HEADER)module;
    auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);
    auto patternBytes = pattern_to_byte(signature);
    auto s = patternBytes.size();
    auto d = patternBytes.data();
    int currentskip = 0;

    if (!sectionName) {
        auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

        for (auto i = 0ul; i < sizeOfImage - s; ++i) {
            if (currentskip < skip) {
                currentskip++;
                continue;
            }

            bool found = true;
            for (auto j = 0ul; j < s; ++j) {
                if (scanBytes[i + j] != d[j] && d[j] != -1) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return (uintptr_t)&scanBytes[i];
            }
        }
    }
    else {
        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            if (strncmp(reinterpret_cast<const char*>(sectionHeader->Name), sectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                auto sectionStart = reinterpret_cast<std::uint8_t*>(module) + sectionHeader->VirtualAddress;
                auto sectionSize = sectionHeader->Misc.VirtualSize;

                for (auto j = 0ul; j < sectionSize - s; ++j) {
                    bool found = true;
                    for (auto k = 0ul; k < s; ++k) {
                        if (sectionStart[j + k] != d[k] && d[k] != -1) {
                            found = false;
                            break;
                        }
                    }
                    if (found) {
                        if (currentskip < skip) {
                            currentskip++;
                            continue;
                        }
                        return (uintptr_t)&sectionStart[j];
                    }
                }
                break; // Stop searching if section is found
            }
        }
    }
    return (uintptr_t)nullptr;
}