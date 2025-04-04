#pragma once

namespace opcodes {
	unsigned char mov_rdi_XXXX[ ] = { 0x48, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // to fill up
	unsigned char mov_rax_rcx[ ] = { 0x48, 0x89, 0xC8 };
}

typedef uintptr_t( *decryption_func )( );
struct decryption_struct {
	bool initialized;
	unsigned char rdi[ 100 ];
	Instruction* Start;
	decryption_func function;
};

std::unordered_map<std::string , decryption_struct> decryption_map;

/// <param name="name"> - Decryption name </param>
/// <param name="address"> - Decryption function address </param>
/// <param name="parameter1"> - will be read at 0x18 and used as parameter for the decryption </param>
/// <param name="Il2CPPHANDLE"> - automatically pass the return inside Il2cppGetHandle </param>
/// <returns></returns>
uintptr_t CallDecryption( std::string name , uintptr_t address , uintptr_t parameter1) {
	if ( !decryption_map[ name ].initialized ) {
		Instruction* Function_Prologue_End = find_inst( ( uintptr_t )address , ZYDIS_MNEMONIC_SUB , ZYDIS_REGISTER_RSP , 0 , 0 ); // Function prologue is literally the start of a function, where push its base pointer and other things in the stack.
		Instruction* Function_Epilogue = find_inst( ( uintptr_t )address , ZYDIS_MNEMONIC_ADD , ZYDIS_REGISTER_RSP , 0 , 0 );     // Function epilogue reverses the actions of the function prologue and returns control to the calling function.

		decryption_map[ name ].Start = find_displacement( ( uintptr_t )address , ZYDIS_MNEMONIC_MOV , ZYDIS_REGISTER_RDI , 1 );   // Decryption Start | example : mov rax, [rdi+18h] ----------------------------------------------------------------------|
		Instruction* End = find_inst( ( uintptr_t )address , ZYDIS_MNEMONIC_JMP , 0 , 0 );                                        // Decryption End                                                                                                        |
		//                                                                                                                                                                                                                                                 |
		int PrologueEnd_To_DecryptionStart = ( decryption_map[ name ].Start->address - ( Function_Prologue_End->address + Function_Prologue_End->instruction.length ) ); //                                                                                |
		int DecryptionEnd_To_Epilogue = Function_Epilogue->address - End->address; //																																									   |
		//                                                                                                                                                                                                                                                 | 
		memset( ( void* )( Function_Prologue_End->address + Function_Prologue_End->instruction.length ) , 0x90 , PrologueEnd_To_DecryptionStart ); // nop everything from Prologue to Encryption Start                                                     |
		memset( ( void* )( End->address ) , 0x90 , DecryptionEnd_To_Epilogue );                                                                    // nop everything from DecryptionEnd To Epilogue Start                                                  |
		//                                                                                                                                                                                                                                                 |
		memcpy( ( void* )( Function_Epilogue->address - sizeof( opcodes::mov_rax_rcx ) ) , opcodes::mov_rax_rcx , sizeof( opcodes::mov_rax_rcx ) ); // append ( mov rax,rcx ) to the Epilogue Start as following microsoft abi rax is the return register. |
		//                                                                                                                                                                                                                                                 |          
		*( uintptr_t* )&opcodes::mov_rdi_XXXX[ 0x2 ] = ( uintptr_t )&decryption_map[ name ].rdi; //                                                                                                                                                        |
		memcpy( ( void* )( decryption_map[ name ].Start->address - sizeof( opcodes::mov_rdi_XXXX ) ) , opcodes::mov_rdi_XXXX , sizeof( opcodes::mov_rdi_XXXX ) ); // normally decryption take RDI as parameter --------------------------------------------|
		//                                                                                                                                                                                                                                                 |
		decryption_map[ name ].function = ( decryption_func )( ( uintptr_t )( address ) ); //                                                                                                                                                              |
		decryption_map[ name ].initialized = true; //                                                                                                                                                                                                      |
	}   //                                                                                                                                                                                                                                                 |
//                                                                                                                                                                                                                                                      ---/
	*( uintptr_t* )&decryption_map[ name ].rdi[ decryption_map[ name ].Start->operand[ 1 ].mem.disp.value ] = driver->read<uint64_t>( parameter1 + decryption_map[ name ].Start->operand[ 1 ].mem.disp.value );   // Start->operand[1].mem.disp.value = 0x18 | mov rax, [rdi+18h]
	return decryption_map[ name ].function( );
}