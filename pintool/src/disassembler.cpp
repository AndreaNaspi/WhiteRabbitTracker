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

/* ===================================================================== */
/* Function to initialize the disassembler                               */
/* ===================================================================== */
int initializeDisassembler() {
	W::BOOL bWow64;
	W::IsWow64Process((W::HANDLE)(-1), &bWow64);

	// Initialize decoder context
    ZydisDecoderInit(&decoder, (bWow64 != 0) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32, 
		                       (bWow64 != 0) ? ZYDIS_ADDRESS_WIDTH_64  : ZYDIS_ADDRESS_WIDTH_32);
    
	// Initialize formatter context
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    return 0;
}