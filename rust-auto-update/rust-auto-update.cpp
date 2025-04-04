#include "misc/include.hpp"

namespace Patterns {
	const char* BaseNetworkable = "48 8B ? ? ? ? ? 48 8B ? ? ? ? ? 48 8B ? ? ? ? ? 48 8B 48 ? E8 ? ? ? ? 48 85 C0 0F ? ? ? ? ? 48 8B 53 ? 45 33 C0 48 8B C8";
    const char* Il2CppGetHandle = "48 8D 0D ? ? ? ? E8 ? ? ? ? 89 45 ? 0F 57 C0";
    const char* MainCamera_C = "20 80 ? ? ? ? ? 00 48 8B D9 75 29 48 ? ? ? ? ? ? E8 ? ? ? ? F0 83 0C 24 00 48 ? ? ? ? ? ? E8 ? ? ? ? F0 83 0C 24 00 C6 ? ? ? ? ? 01 48 8B ? ? ? ? ? 48 8B ? ? 00";
}

namespace Address {
    uintptr_t GameAssembly;
	Instruction* BaseNetworkable;
    Instruction* Il2CppGetHandle;
	Instruction* MainCamera_C;

    uintptr_t BaseNetworkable_Decryption;
    uintptr_t BaseNetworkable_DecryptList;
}

namespace offsets {
    void baseNetworkable() {
		BaseNetworkable::BaseNetworkable_C = extract_value(Address::BaseNetworkable, 1, true, Address::GameAssembly);
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

        BaseNetworkable::static_fields = StaticFields->operand[1].mem.disp.value;
        BaseNetworkable::wrapper_class_ptr = WrapperClassPtr->operand[1].mem.disp.value;
        BaseNetworkable::parent_static_fields = _parent_static_fields->operand[1].mem.disp.value;
        BaseNetworkable::entity = _entity->operand[1].mem.disp.value;
    }

    void others( ) {
		Il2cppHandle = extract_value( Address::Il2CppGetHandle , 1 , true , Address::GameAssembly );
        camera::MainCamera_C = extract_value( find_inst( Address::MainCamera_C->address , ZYDIS_MNEMONIC_LEA ), 1, true, Address::GameAssembly );
        Instruction* MainCameraChain1 = find_displacement( Address::MainCamera_C->address , ZYDIS_MNEMONIC_MOV , ZYDIS_REGISTER_RAX , 1 );
        Instruction* MainCameraChain2 = find_displacement( Address::MainCamera_C->address , ZYDIS_MNEMONIC_MOV , ZYDIS_REGISTER_RCX , 1 );
        Instruction* MainCameraChain3 = find_displacement( Address::MainCamera_C->address , ZYDIS_MNEMONIC_CMP , ZYDIS_REGISTER_RDI , 0 );
        camera::MainCamera_Chain1 = MainCameraChain1->operand[1].mem.disp.value;
        camera::MainCamera_Chain2 = MainCameraChain2->operand[1].mem.disp.value;
        camera::MainCamera_Chain3 = MainCameraChain3->operand[0].mem.disp.value;
    }
}

inline uintptr_t Il2cppGetHandle(int32_t ObjectHandleID) {

    uint64_t rdi_1 = ObjectHandleID >> 3;
    uint64_t rcx_1 = (ObjectHandleID & 7) - 1;
    uint64_t baseAddr = Address::GameAssembly + offsets::Il2cppHandle + rcx_1 * 0x28;
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

void CheatLoop() {

    while (true) {
        uintptr_t base_networkable = driver->read<uintptr_t>(Address::GameAssembly + offsets::BaseNetworkable::BaseNetworkable_C);
        uintptr_t static_fields = driver->read<uintptr_t>(base_networkable + offsets::BaseNetworkable::static_fields);
        uintptr_t wrapper_class_ptr = driver->read<uintptr_t>(static_fields + offsets::BaseNetworkable::wrapper_class_ptr);
        uintptr_t wrapper_class = Il2cppGetHandle(CallDecryption("BaseNetworkable", Address::BaseNetworkable_Decryption, wrapper_class_ptr));
        uintptr_t parent_static_fields = driver->read<uint64_t>(wrapper_class + offsets::BaseNetworkable::parent_static_fields);
        uintptr_t parent_class = Il2cppGetHandle(CallDecryption("BaseNetworkable_DecryptList", Address::BaseNetworkable_DecryptList, parent_static_fields));
        uint64_t entity = driver->read<uint64_t>(parent_class + offsets::BaseNetworkable::entity);

        uintptr_t firstval = driver->read<uint64_t>(entity + 0x10);
        uintptr_t secondval = driver->read<uint64_t>(entity + 0x18);

        auto EntityCount = firstval < secondval ? firstval : secondval;
        auto EntityList = firstval < secondval ? secondval : firstval;

		uintptr_t LocalPlayer = driver->read<uintptr_t>( ( uint64_t )EntityList + 0x20 );
		if ( !LocalPlayer ) continue;

		uintptr_t playermodel = driver->read<uintptr_t>( LocalPlayer + 0x280 );                       // these offsets are not auto updating , it will be up to you 😉❤️
		sdk::structs::Vector3 playerpos = driver->read<sdk::structs::Vector3>( playermodel + 0x1D8 ); // these offsets are not auto updating , it will be up to you 😉❤️

		system("cls");
		std::cout << "Entity List: 0x" << std::hex << EntityList << std::endl;
		std::cout << "Entity Count: " << std::dec << ( int )EntityCount << std::endl;
		std::cout << "LocalPlayer pos.x: " << playerpos.x << " | pos.y: " << playerpos.y << " | pos.z: " << playerpos.z << std::endl;
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

    if ( !( Address::Il2CppGetHandle = get_instruction( PatternScan( ( void* )Address::GameAssembly , Patterns::Il2CppGetHandle ) ) ) ) {
        printf( "Failed to find Il2CppGetHandle Pattern!\n" );
        return false;
    }

    if ( !( Address::MainCamera_C = get_instruction( PatternScan( ( void* )Address::GameAssembly , Patterns::MainCamera_C ) ) ) ) {
        printf( "Failed to find MainCamera_C Pattern!\n" );
        return false;
    }

    offsets::baseNetworkable();
    offsets::others( );
    
    return FreeLibrary((HMODULE)Address::GameAssembly);
}

int main() {
    if (Init())
        CheatLoop();
}
