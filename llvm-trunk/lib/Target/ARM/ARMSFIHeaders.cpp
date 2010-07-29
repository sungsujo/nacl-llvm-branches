//===-- ARMSFIHeaders.cpp - Print SFI headers to an ARM .s file -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the initial header string needed
// for the Native Client target in ARM assembly.
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include <string>


using namespace llvm;

extern cl::opt<bool> FlagSfiZeroMask;
extern cl::opt<bool> FlagSfiStore;
extern cl::opt<bool> FlagSfiStack;
extern cl::opt<bool> FlagSfiBranch;
extern cl::opt<bool> FlagSfiData;


void EmitSFIHeaders(raw_ostream &O) {
  O << " @ ========================================\n";
  O << "@ Branch: " << FlagSfiBranch << "\n";
  O << "@ Stack: " << FlagSfiStack << "\n";
  O << "@ Store: " << FlagSfiStore << "\n";
  O << "@ Data: " << FlagSfiData << "\n";

  O << " @ ========================================\n";
  // NOTE: this macro does bundle alignment as follows
  //       if current bundle pos is X emit pX data items of value "val"
  // NOTE: that pos will be one of: 0,4,8,12
  //
  O <<
    "\t.macro sfi_long_based_on_pos p0 p1 p2 p3 val\n"
    "\t.set pos, (. - XmagicX) % 16\n"
    "\t.fill  (((\\p3<<12)|(\\p2<<8)|(\\p1<<4)|\\p0)>>pos) & 15, 4, \\val\n"
    "\t.endm\n"
    "\n\n";

  O <<
    "\t.macro sfi_illegal_if_at_bundle_begining\n"
    "\tsfi_long_based_on_pos 1 0 0 0 0xe1277777\n"
    "\t.endm\n"
    "\n\n";

  O <<
    "\t.macro sfi_nop_if_at_bundle_end\n"
    "\tsfi_long_based_on_pos 0 0 0 1 0xe1a00000\n"
    "\t.endm\n"
      "\n\n";

  O <<
    "\t.macro sfi_nops_to_force_slot3\n"
    "\tsfi_long_based_on_pos 3 2 1 0 0xe1a00000\n"
    "\t.endm\n"
    "\n\n";

  O <<
    "\t.macro sfi_nops_to_force_slot2\n"
    "\tsfi_long_based_on_pos 2 1 0 3 0xe1a00000\n"
    "\t.endm\n"
    "\n\n";

  O <<
    "\t.macro sfi_nops_to_force_slot1\n"
    "\tsfi_long_based_on_pos 1 0 3 2 0xe1a00000\n"
    "\t.endm\n"
    "\n\n";

  O << " @ ========================================\n";
  if (FlagSfiZeroMask) {
    O <<
      "\t.macro sfi_data_mask reg cond\n"
      "\tbic\\cond \\reg, \\reg, #0\n"
      "\t.endm\n"
      "\n\n";

    O <<
      "\t.macro sfi_code_mask reg cond=\n"
      "\tbic\\cond \\reg, \\reg, #0\n"
      "\t.endm\n"
      "\n\n";

  } else {
    O <<
      "\t.macro sfi_data_mask reg cond\n"
      "\tbic\\cond \\reg, \\reg, #0xc0000000\n"
      "\t.endm\n"
      "\n\n";

    O <<
      "\t.macro sfi_data_tst reg\n"
      "\ttst \\reg, #0xc0000000\n"
      "\t.endm\n"
      "\n\n";

    O <<
      "\t.macro sfi_code_mask reg cond=\n"
      "\tbic\\cond \\reg, \\reg, #0xc000000f\n"
      "\t.endm\n"
      "\n\n";
  }

  O << " @ ========================================\n";
  if (FlagSfiBranch) {
    O <<
      "\t.macro sfi_call_preamble cond=\n"
      "\tsfi_nops_to_force_slot3\n"
      "\t.endm\n"
      "\n\n";

    O <<
      "\t.macro sfi_return_preamble reg cond=\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tsfi_code_mask \\reg \\cond\n"
      "\t.endm\n"
      "\n\n";
    
    // This is used just before "bx rx"
    O <<
      "\t.macro sfi_indirect_jump_preamble link cond=\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tsfi_code_mask \\link \\cond\n"
      "\t.endm\n"
      "\n\n";

    // This is use just before "blx rx"
    O <<
      "\t.macro sfi_indirect_call_preamble link cond=\n"
      "\tsfi_nops_to_force_slot2\n"
      "\tsfi_code_mask \\link \\cond\n"
      "\t.endm\n"
      "\n\n";

  }

  if (FlagSfiStore) {
    O << " @ ========================================\n";

    O <<
      "\t.macro sfi_store_preamble reg cond\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tsfi_data_mask \\reg, \\cond\n"
      "\t.endm\n"
      "\n\n";

    O <<
      "\t.macro sfi_cstore_preamble reg\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tsfi_data_tst \\reg\n"
      "\t.endm\n"
      "\n\n";
  } else {
    O <<
      "\t.macro sfi_store_preamble reg cond\n"
      "\t.endm\n"
      "\n\n";

    O <<
      "\t.macro sfi_cstore_preamble reg cond\n"
      "\t.endm\n"
      "\n\n";
  }

  const char* kPreds[] = {
    "eq",
    "ne",
    "lt",
    "le",
    "ls",
    "ge",
    "gt",
    "hs",
    "hi",
    "lo",
    "mi",
    "pl",
    NULL,
  };

  if (FlagSfiStack) {

    O << " @ ========================================\n";

    O <<
      "\t.macro sfi_add rega regb imm rot=0\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tadd \\rega, \\regb, \\imm, \\rot\n"
      "\tsfi_data_mask \\rega\n"
      "\t.endm\n"
      "\n\n";

    for (int p=0; kPreds[p] != NULL; ++p) {
      O <<
        "\t.macro sfi_add" << kPreds[p] << " rega regb imm rot=0\n"
        "\tsfi_nop_if_at_bundle_end\n"
        "\tadd" << kPreds[p] << " \\rega, \\regb, \\imm, \\rot\n"
        "\tsfi_data_mask \\rega, " << kPreds[p] << "\n"
        "\t.endm\n"
        "\n\n";
    }

    O << " @ ========================================\n";
    O <<
      "\t.macro sfi_sub rega regb imm rot=0\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tsub \\rega, \\regb, \\imm, \\rot\n"
      "\tsfi_data_mask \\rega\n"
      "\t.endm\n"
      "\n\n";

    for (int p=0; kPreds[p] != NULL; ++ p) {
      O <<
        "\t.macro sfi_sub" << kPreds[p] << " rega regb imm rot=0\n"
        "\tsfi_nop_if_at_bundle_end\n"
        "\tsub" << kPreds[p] << " \\rega, \\regb, \\imm, \\rot\n"
        "\tsfi_data_mask \\rega, " << kPreds[p] << "\n"
        "\t.endm\n"
        "\n\n";
    }

    O << " @ ========================================\n";

    O <<
      "\t.macro sfi_mov rega regb\n"
      "\tsfi_nop_if_at_bundle_end\n"
      "\tmov \\rega, \\regb\n"
      "\tsfi_data_mask \\rega\n"
      "\t.endm\n"
      "\n\n";

    for (int p=0; kPreds[p] != NULL; ++ p) {
      O <<
        "\t.macro mov_sub" << kPreds[p] << " rega regb imm rot=0\n"
        "\tsfi_nop_if_at_bundle_end\n"
        "\tmov" << kPreds[p] << " \\rega, \\regb, \\imm, \\rot\n"
        "\tsfi_data_mask \\rega, " << kPreds[p] << "\n"
        "\t.endm\n"
        "\n\n";
    }

  } // FlagSfiStack
  
  O << " @ ========================================\n";
  O << "\t.text\n";
}
