#include "misc/include.hpp"

namespace Patterns {
	const char* BaseNetworkable = "48 8B 05 ? ? ? ? 48 8B 80 ? ? ? ? 48 8B 15 ? ? ? ? 48 8B 48 ? E8 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 45 33 C0 48 8B D3 48 8B C8 E8 ? ? ? ? 48 8B 0D ? ? ? ? 48 8B D8";
}

namespace Address {
    uintptr_t GameAssembly;
	Instruction* BaseNetworkable;

    uintptr_t BaseNetworkable_Decryption;
    uintptr_t BaseNetworkable_DecryptList;
}

namespace offsets {
	uintptr_t BaseNetworkable_C, static_fields, wrapper_class_ptr, parent_static_fields, entity;
    namespace get {
        void BaseNetworkable() {
            BaseNetworkable_C = extract_value(Address::BaseNetworkable, 1, true, Address::GameAssembly);
            Instruction* StaticFields = find_displacement(Address::BaseNetworkable->address, ZYDIS_MNEMONIC_MOV, ZYDIS_REGISTER_RAX, 1);
            Instruction* WrapperClassPtr = find_displacement(Address::BaseNetworkable->address, ZYDIS_MNEMONIC_MOV, ZYDIS_REGISTER_RAX, 1, 1);
            
            Instruction* BaseNetworkable_decryption_inst = find_inst(WrapperClassPtr->next->address, ZYDIS_MNEMONIC_CALL);
            uintptr_t    BaseNetworkable_decryption = get_call_value(BaseNetworkable_decryption_inst);

            Instruction* fnc_get_player_list_inst = find_inst(BaseNetworkable_decryption_inst->next->address, ZYDIS_MNEMONIC_CALL);
            uintptr_t    fnc_get_player_list = get_call_value(fnc_get_player_list_inst);

            Instruction* _parent_static_fields = find_displacement(fnc_get_player_list, ZYDIS_MNEMONIC_MOV, ZYDIS_REGISTER_RDI, 1);
            Instruction* _entity = find_displacement(fnc_get_player_list, ZYDIS_MNEMONIC_MOV, ZYDIS_REGISTER_RSI, 1);
            
            Instruction* BaseNetworkable_DecryptList_inst = find_inst(_parent_static_fields->address, ZYDIS_MNEMONIC_CALL);
            uintptr_t    BaseNetworkable_DecryptList = get_call_value(BaseNetworkable_DecryptList_inst);

            Address::BaseNetworkable_Decryption = (uintptr_t)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			memcpy((void*)Address::BaseNetworkable_Decryption, (void*)BaseNetworkable_decryption, 0x10000);

            Address::BaseNetworkable_DecryptList = (uintptr_t)VirtualAlloc(nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            memcpy((void*)Address::BaseNetworkable_DecryptList, (void*)BaseNetworkable_DecryptList, 0x10000);

            static_fields = StaticFields->operand[1].mem.disp.value;
            wrapper_class_ptr = WrapperClassPtr->operand[1].mem.disp.value;
            parent_static_fields = _parent_static_fields->operand[1].mem.disp.value;
            entity = _entity->operand[1].mem.disp.value;
        }
    }
}

inline uintptr_t Il2cppGetHandle(int32_t ObjectHandleID) {

    uint64_t rdi_1 = ObjectHandleID >> 3;
    uint64_t rcx_1 = (ObjectHandleID & 7) - 1;
    uint64_t baseAddr = Address::GameAssembly + 0xBF43170 + rcx_1 * 0x28;
    uint32_t limit = driver->read<uint32_t>(baseAddr + 0x10);
    if (rdi_1 < limit) {
        uintptr_t objAddr = driver->read<uintptr_t>(baseAddr);
        uint32_t bitMask = driver->read<uint32_t>(objAddr + ((rdi_1 >> 5) << 2));
        if (TEST_BITD(bitMask, rdi_1 & 0x1f)) {
            uintptr_t ObjectArray = driver->read<uintptr_t>(baseAddr + 0x8) + (rdi_1 << 3);
            return driver->read<BYTE>(baseAddr + 0x14) > 1
                ? driver->read<uintptr_t>(ObjectArray)
                : ~driver->read<uint32_t>(ObjectArray);
        }
    }
    return 0;
}

namespace opcodes {
    unsigned char mov_rdi_XXXX[] = { 0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // to fill up
    unsigned char mov_rax_rcx[] = { 0x48, 0x89, 0xC8 };
}

typedef uintptr_t(*decryption_func)();
struct decryption_struct {
	bool initialized;
    unsigned char rdi[100];
    Instruction* Start;
    decryption_func function;
};

std::unordered_map<std::string, decryption_struct> decryption_map;

/// <param name="name"> - Decryption name </param>
/// <param name="address"> - Decryption function address </param>
/// <param name="parameter1"> - will be read at 0x18 and used as parameter for the decryption </param>
/// <param name="Il2CPPHANDLE"> - automatically pass the return inside Il2cppGetHandle </param>
/// <returns></returns>
uintptr_t CallDecryption(std::string name,uintptr_t address, uintptr_t parameter1, bool Il2CPPHANDLE = true) {
	if (!decryption_map[name].initialized) {
        Instruction* Function_Prologue_End = find_inst((uintptr_t)address, ZYDIS_MNEMONIC_SUB, ZYDIS_REGISTER_RSP,0,0); // Function prologue is literally the start of a function, where push its base pointer and other things in the stack.
        Instruction* Function_Epilogue = find_inst((uintptr_t)address, ZYDIS_MNEMONIC_ADD, ZYDIS_REGISTER_RSP, 0, 0);   // Function epilogue reverses the actions of the function prologue and returns control to the calling function.
        
        decryption_map[name].Start = find_displacement((uintptr_t)address, ZYDIS_MNEMONIC_MOV, ZYDIS_REGISTER_RDI, 1);  // Decryption Start | example : mov rax, [rdi+18h] -----------------------------------------------------------------------|
        Instruction* End = find_inst((uintptr_t)address, ZYDIS_MNEMONIC_JMP, 0, 0);                                     // Decryption End                                                                                                         |
//                                                                                                                                                                                                                                                |
        int PrologueEnd_To_DecryptionStart = (decryption_map[name].Start->address - (Function_Prologue_End->address + Function_Prologue_End->instruction.length)); //                                                                             |
        int DecryptionEnd_To_Epilogue = Function_Epilogue->address - End->address; //                                                                                                                                                             |
//                                                                                                                                                                                                                                                |
        memset((void*)(Function_Prologue_End->address + Function_Prologue_End->instruction.length), 0x90, PrologueEnd_To_DecryptionStart); // nop everything from Prologue to Encryption Start                                                    |
        memset((void*)(End->address), 0x90, DecryptionEnd_To_Epilogue);                                                                    // nop everything from DecryptionEnd To Epilogue Start                                                 |
//                                                                                                                                                                                                                                                |
		memcpy((void*)(Function_Epilogue->address - sizeof(opcodes::mov_rax_rcx)), opcodes::mov_rax_rcx, sizeof(opcodes::mov_rax_rcx));    // append ( mov rax,rcx ) to the Epilogue Start as following microsoft abi rax is the return register. |
//                                                                                                                                                                                                                                                |          
        *(uintptr_t*)&opcodes::mov_rdi_XXXX[0x2] = (uintptr_t)&decryption_map[name].rdi; //                                                                                                                                                       |
        memcpy((void*)(decryption_map[name].Start->address - sizeof(opcodes::mov_rdi_XXXX)), opcodes::mov_rdi_XXXX, sizeof(opcodes::mov_rdi_XXXX)); // normally decryption take RDI as parameter ------------------------------------------------/|
//                                                                                                                                                                                                                                              /
        decryption_map[name].function = (decryption_func)((uintptr_t)(address)); //                                                                                                                                                            /
        decryption_map[name].initialized = true; //                                                                                                                                                                                           / 
    }   //                                                                                                                                                                                                                                   /
//                                                                                                                                                                                                                                      ----/
	*(uintptr_t*)&decryption_map[name].rdi[decryption_map[name].Start->operand[1].mem.disp.value] = driver->read<uint64_t>(parameter1 + decryption_map[name].Start->operand[1].mem.disp.value);   // Start->operand[1].mem.disp.value = 0x18 | mov rax, [rdi+18h]
    return Il2CPPHANDLE ? Il2cppGetHandle(decryption_map[name].function()) : decryption_map[name].function();
}

void CheatLoop() {

    while (true) {
        uintptr_t base_networkable = driver->read<uintptr_t>(Address::GameAssembly + offsets::BaseNetworkable_C);
        uintptr_t static_fields = driver->read<uintptr_t>(base_networkable + offsets::static_fields);
        uintptr_t wrapper_class_ptr = driver->read<uintptr_t>(static_fields + offsets::wrapper_class_ptr);
        uintptr_t wrapper_class = CallDecryption("BaseNetworkable", Address::BaseNetworkable_Decryption, wrapper_class_ptr);
        uintptr_t parent_static_fields = driver->read<uint64_t>(wrapper_class + offsets::parent_static_fields);
        uintptr_t parent_class = CallDecryption("BaseNetworkable_DecryptList", Address::BaseNetworkable_DecryptList, parent_static_fields);
        uint64_t entity = driver->read<uint64_t>(parent_class + offsets::entity);

        auto EntityCount = driver->read<uint32_t>(entity + 0x10);
        auto EntityList = driver->read<uint64_t>(entity + 0x18);

		system("cls");
		std::cout << "Entity List: 0x" << std::hex << EntityList << std::endl;
        std::cout << "Entity Count: " << std::dec << (int)EntityCount << std::endl;
        Sleep(400);
    }
}

bool Init() {
    driver = new Driver();
    driver->init("RustClient.exe");

    Address::GameAssembly = (uintptr_t)LoadLibraryExW(L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Rust\\GameAssembly.dll", nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (!Address::GameAssembly) {
        printf("Failed to load GameAssembly.dll!\n");
        return false;
    }

    if (!(Address::BaseNetworkable = get_instruction(PatternScan((void*)Address::GameAssembly, Patterns::BaseNetworkable)))) {
        printf("Failed to find BaseNetworkable Pattern!\n");
        return false;
    }

    offsets::get::BaseNetworkable();
    
    return FreeLibrary((HMODULE)Address::GameAssembly);
}

int main() {
    if (Init())
        CheatLoop();
}