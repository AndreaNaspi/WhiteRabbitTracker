/* ================================================================== */
/* Imports                                                            */
/* ================================================================== */
#pragma once
#include "disassembler.h"

/* ================================================================== */
/* Global variables                                                   */
/* ================================================================== */

// Decoder context
ZydisDecoder decoder;

// Formatter context
ZydisFormatter formatter;

std::string disassembleInstruction(ADDRINT address, ADDRINT instructionSize) {
    ZyanUSize offset = 0;
    ZydisDecodedInstruction instruction;
    ZyanU64 runtime_address = address;
    std::string result;
    while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(address + offset), instructionSize - offset, &instruction)))
    {
        // Format & print the binary instruction structure to human readable format
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer), runtime_address);
        result += buffer;
        offset += instruction.length;
        runtime_address += instruction.length;
    }
    return result;
}

/* ===================================================================== */
/* Function to initialize the disassembler                               */
/* ===================================================================== */
int initializeDisassembler() {
	// Initialize decoder context
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32))) {
        return EXIT_FAILURE;
    }
    
	// Initialize formatter context
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}