#pragma once

struct Instruction {
    Instruction* prev;
    Instruction* next;
    uintptr_t address;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operand[ZYDIS_MAX_OPERAND_COUNT];
    char buffer[256];
};


void PrintInstruction(Instruction* instruction) {
    std::cout << "0x" << std::hex << std::uppercase << instruction->address;
    std::cout << "    " << instruction->buffer << std::endl;
}

Instruction* find_inst(uintptr_t start_address, int MNEMONIC_STOP = 0, int reg = 0, int op = 0, bool buildnext = true, int size = 0x1000) {
    ZyanU64 runtime_address = start_address;
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecoder decoder;
    ZydisFormatter formatter;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisDecodedOperand operand[ZYDIS_MAX_OPERAND_COUNT];
    ZyanU8* data = (ZyanU8*)(start_address);

    Instruction* head = nullptr; 
    Instruction* prev_inst = nullptr;
    Instruction* matched_inst = nullptr;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &decoder,
        data + offset,
        size,
        &instruction,
        operand))) {

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operand,
            instruction.operand_count_visible, &buffer[0], sizeof(buffer), runtime_address,
            ZYAN_NULL);

        Instruction* current_inst = new Instruction();
        current_inst->address = runtime_address;
        current_inst->instruction = instruction;
        memcpy(current_inst->buffer, buffer, sizeof(buffer));
        memcpy(current_inst->operand, operand, sizeof(operand));
        current_inst->prev = prev_inst;
        current_inst->next = nullptr;

        if (prev_inst) {
            prev_inst->next = current_inst;
        }
        else {
            head = current_inst; 
        }

        prev_inst = current_inst;

        if (instruction.mnemonic == MNEMONIC_STOP and !matched_inst) {
            if(!reg)
                matched_inst = current_inst;
			else if (operand[op].type == ZYDIS_OPERAND_TYPE_REGISTER &&
				operand[op].reg.value == reg) {
                matched_inst = current_inst;
			}
        }

        if(!buildnext and matched_inst){
            return matched_inst;
        }
        offset += instruction.length;
        runtime_address += instruction.length;
    }

    return matched_inst;
}

Instruction* get_instruction(uintptr_t start_address, int size = 0x1000) {
    ZyanU64 runtime_address = start_address;
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecoder decoder;
    ZydisFormatter formatter;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanU8* data = (ZyanU8*)(start_address);

    Instruction* head = nullptr;
    Instruction* prev_inst = nullptr;
    Instruction* matched_inst = nullptr;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &decoder,
        data + offset,
        size,
        &instruction,
        operands))) {

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
            instruction.operand_count_visible, buffer, sizeof(buffer),
            runtime_address, ZYAN_NULL);

        // Create instruction node for every instruction
        Instruction* current_inst = new Instruction();
        current_inst->address = runtime_address;
        current_inst->instruction = instruction;
        memcpy(current_inst->buffer, buffer, sizeof(buffer));
        memcpy(current_inst->operand, operands, sizeof(operands));
        current_inst->prev = prev_inst;
        current_inst->next = nullptr;

        // Link to previous instruction
        if (prev_inst) {
            prev_inst->next = current_inst;
        }
        else {
            head = current_inst;  // First node in list
        }

        // Check if this is the pattern we're looking for
		if (!matched_inst) {
            matched_inst = current_inst;
        }

        prev_inst = current_inst;
        offset += instruction.length;
        runtime_address += instruction.length;

        // Safety check to prevent infinite loops
        if (offset >= size) break;
    }

    return matched_inst;  // Returns nullptr if no match found, but list is still complete
}

Instruction* find_displacement(uintptr_t start_address, int mnemonic = 0, int reg = 0, int operand = 0, int skips = 0, int size = 0x1000) {
    ZyanU64 runtime_address = start_address;
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecoder decoder;
    ZydisFormatter formatter;

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanU8* data = (ZyanU8*)(start_address);

    Instruction* head = nullptr;
    Instruction* prev_inst = nullptr;
    Instruction* matched_inst = nullptr;
    int currentskip = 0;

    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(
        &decoder,
        data + offset,
        size,
        &instruction,
        operands))) {

        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
            instruction.operand_count_visible, buffer, sizeof(buffer),
            runtime_address, ZYAN_NULL);

        // Create instruction node for every instruction
        Instruction* current_inst = new Instruction();
        current_inst->address = runtime_address;
        current_inst->instruction = instruction;
        memcpy(current_inst->buffer, buffer, sizeof(buffer));
        memcpy(current_inst->operand, operands, sizeof(operands));
        current_inst->prev = prev_inst;
        current_inst->next = nullptr;

        // Link to previous instruction
        if (prev_inst) {
            prev_inst->next = current_inst;
        }
        else {
            head = current_inst;  // First node in list
        }

        // Check if this is the pattern we're looking for
        if (!matched_inst and operands[operand].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[operand].mem.base == reg &&
            operands[operand].mem.disp.has_displacement &&
            instruction.mnemonic == mnemonic) {
            if (currentskip == skips) {
                matched_inst = current_inst;
            }
            
            currentskip++;
        }

        prev_inst = current_inst;
        offset += instruction.length;
        runtime_address += instruction.length;

        // Safety check to prevent infinite loops
        if (offset >= size) break;
    }

    return matched_inst;  // Returns nullptr if no match found, but list is still complete
}

uintptr_t get_call_value(Instruction* inst) {
    return inst->address + inst->instruction.length + inst->operand[0].imm.value.s;
}

uintptr_t extract_value(Instruction* inst, int operand , bool rva = true, uintptr_t rvato = 0) {
    uint64_t absolute_address = 0;
    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
        &inst->instruction,
        &inst->operand[operand],
        inst->address,
        &absolute_address))) {
        return rva ? absolute_address - rvato : absolute_address;
    }
    return 0;
}