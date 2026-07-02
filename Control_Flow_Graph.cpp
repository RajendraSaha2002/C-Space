// ============================================================
// Project P12: Control Flow Graph (CFG) Builder for x86 Bytecode
// Platform: Windows/Linux/Mac — CLion / GCC / Clang / C++17
// ============================================================
// Components implemented from scratch (zero external libs):
//
//   SECTION 1 — x86-32 Instruction Decoder
//     * Opcode table for all common x86-32 instructions
//     * ModRM / SIB / displacement / immediate parsing
//     * Prefix handling (REP, LOCK, segment overrides)
//     * Instruction length decoder (variable 1-15 bytes)
//     * Mnemonic + operand string formatter
//
//   SECTION 2 — Basic Block Builder
//     * Leader identification (entry, branch targets, post-branch)
//     * Basic block boundary detection
//     * Fall-through vs taken edge classification
//
//   SECTION 3 — CFG Construction
//     * Adjacency list graph representation
//     * Inter-block edge resolution
//     * Unreachable block detection
//     * Dead code identification
//
//   SECTION 4 — CFG Analysis
//     * Dominance tree computation (Cooper algorithm)
//     * Loop detection (back edges in DFS)
//     * Cyclomatic complexity (McCabe metric)
//     * Post-order and reverse post-order traversal
//
//   SECTION 5 — Malware Pattern Detection
//     * Infinite loop detection
//     * Self-modifying jump pattern detection
//     * Dead code block flagging
//     * Suspicious CFG shape heuristics
//     * Obfuscation score computation
//
//   SECTION 6 — DOT Graph Export
//     * Graphviz DOT format output
//     * Node coloring by block type
//     * Edge labeling (taken / fall-through)
//
//   SECTION 7 — Disassembly Listing Printer
//   SECTION 8 — Interactive CLI with sample bytecodes
// ============================================================

#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <stack>
#include <algorithm>
#include <functional>
#include <cstring>
#include <cstdint>
#include <cassert>
#include <limits>

using u8  = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;
using i8  = int8_t;
using i16 = int16_t;
using i32 = int32_t;

// ============================================================
// CONSOLE HELPERS
// ============================================================
static void sep(char c = '-', int w = 72) {
    std::cout << std::string(w, c) << "\n";
}
static void hdr(const std::string& t) {
    sep('=');
    std::cout << "  " << t << "\n";
    sep('=');
}

// ============================================================
// ============================================================
//   SECTION 1 — X86-32 INSTRUCTION DECODER
// ============================================================
// ============================================================
// x86 is a variable-length CISC instruction set.
// Instruction format:
//   [Prefixes 0-4] [Opcode 1-3] [ModRM] [SIB]
//   [Displacement 0/1/2/4] [Immediate 0/1/2/4]
//
// This decoder handles the most common subset needed
// for CFG construction — all control flow instructions
// plus arithmetic, data movement, and stack operations.
// Unknown bytes are decoded as DB (define byte) pseudo-ops.
// ============================================================

// ============================================================
// REGISTER NAMES
// ============================================================
static const char* REG32[8] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi"
};
static const char* REG16[8] = {
    "ax","cx","dx","bx","sp","bp","si","di"
};
static const char* REG8[8] = {
    "al","cl","dl","bl","ah","ch","dh","bh"
};
static const char* SREG[8] = {
    "es","cs","ss","ds","fs","gs","??","??"
};

// ============================================================
// INSTRUCTION CATEGORIES
// Used to identify leaders and edges in the CFG.
// ============================================================
enum class InstrCat {
    NORMAL,        // ordinary instruction, falls through
    UNCOND_JMP,    // JMP rel8/rel32/rm32  (no fall-through)
    COND_JMP,      // Jcc rel8/rel32       (taken + fall-through)
    CALL,          // CALL                 (fall-through only in CFG)
    RET,           // RET / RETN / RETF    (no successors)
    INT,           // INT n                (treated as RET for CFG)
    HLT,           // HLT                  (no successors)
    UNKNOWN        // undecodeable byte
};

// ============================================================
// DECODED INSTRUCTION
// ============================================================
struct Instr {
    u32         offset   = 0;       // byte offset from buffer start
    u8          len      = 0;       // total instruction length
    std::string mnemonic;           // e.g. "JNZ", "MOV", "PUSH"
    std::string operands;           // formatted operand string
    InstrCat    cat      = InstrCat::NORMAL;
    bool        has_target = false;
    u32         target   = 0;       // branch target absolute offset
    bool        has_fallthrough = true;

    std::string to_string() const {
        std::ostringstream oss;
        oss << std::hex << std::setw(8)
            << std::setfill('0') << offset << "  ";
        // raw bytes placeholder (filled by disassembler)
        if (!operands.empty())
            oss << std::left << std::setw(10) << mnemonic
                << operands;
        else
            oss << mnemonic;
        return oss.str();
    }
};

// ============================================================
// X86 DISASSEMBLER
// Variable-length instruction decoder for x86-32.
// ============================================================
class X86Decoder {
public:
    // --------------------------------------------------------
    // Decode one instruction at buf[offset], buf_len = total size.
    // Returns decoded Instr. On failure returns DB pseudo-op.
    // --------------------------------------------------------
    static Instr decode(const u8* buf, size_t buf_len,
                         u32 offset) {
        Instr ins;
        ins.offset = offset;

        if (offset >= buf_len) {
            ins.mnemonic = "???";
            ins.len = 1;
            ins.cat = InstrCat::UNKNOWN;
            return ins;
        }

        const u8* p   = buf + offset;
        size_t    rem = buf_len - offset;
        size_t    pos = 0;  // position within instruction bytes

        // ---- Prefix accumulation ----
        bool prefix_lock  = false;
        bool prefix_rep   = false;
        bool prefix_repne = false;
        bool opsz_override = false; // 0x66: operand size override
        bool addrsz_override = false; // 0x67
        int  seg_override = -1;

        // Collect up to 4 legacy prefixes
        for (int pfx = 0; pfx < 4 && pos < rem; pfx++) {
            u8 b = p[pos];
            if (b == 0xF0) { prefix_lock  = true; pos++; }
            else if (b == 0xF2) { prefix_repne = true; pos++; }
            else if (b == 0xF3) { prefix_rep   = true; pos++; }
            else if (b == 0x26) { seg_override = 0; pos++; } // ES
            else if (b == 0x2E) { seg_override = 1; pos++; } // CS
            else if (b == 0x36) { seg_override = 2; pos++; } // SS
            else if (b == 0x3E) { seg_override = 3; pos++; } // DS
            else if (b == 0x64) { seg_override = 4; pos++; } // FS
            else if (b == 0x65) { seg_override = 5; pos++; } // GS
            else if (b == 0x66) { opsz_override = true; pos++; }
            else if (b == 0x67) { addrsz_override = true; pos++; }
            else break;
        }
        (void)prefix_lock; (void)prefix_rep;
        (void)prefix_repne; (void)addrsz_override;
        (void)seg_override;

        if (pos >= rem) {
            ins.mnemonic = "DB";
            ins.operands = hex_byte(p[0]);
            ins.len      = 1;
            ins.cat      = InstrCat::UNKNOWN;
            return ins;
        }

        u8 op = p[pos++];

        // ============================================================
        // OPCODE DISPATCH TABLE
        // ============================================================

        // ---- NOP ----
        if (op == 0x90) {
            ins.mnemonic = "NOP";
            ins.cat      = InstrCat::NORMAL;
        }

        // ---- PUSH r32 (0x50-0x57) ----
        else if (op >= 0x50 && op <= 0x57) {
            ins.mnemonic = "PUSH";
            ins.operands = REG32[op - 0x50];
        }

        // ---- POP r32 (0x58-0x5F) ----
        else if (op >= 0x58 && op <= 0x5F) {
            ins.mnemonic = "POP";
            ins.operands = REG32[op - 0x58];
        }

        // ---- PUSH imm8 ----
        else if (op == 0x6A) {
            if (pos < rem) {
                ins.mnemonic = "PUSH";
                ins.operands = "byte " + hex_byte(p[pos++]);
            }
        }

        // ---- PUSH imm32 ----
        else if (op == 0x68) {
            if (pos + 3 < rem) {
                u32 imm = read_u32(p + pos); pos += 4;
                ins.mnemonic = "PUSH";
                ins.operands = "dword 0x" + hex32(imm);
            }
        }

        // ---- MOV r32, imm32 (0xB8-0xBF) ----
        else if (op >= 0xB8 && op <= 0xBF) {
            if (pos + 3 < rem) {
                u32 imm = read_u32(p + pos); pos += 4;
                ins.mnemonic = "MOV";
                ins.operands = std::string(REG32[op - 0xB8])
                               + ", 0x" + hex32(imm);
            }
        }

        // ---- MOV r8, imm8 (0xB0-0xB7) ----
        else if (op >= 0xB0 && op <= 0xB7) {
            if (pos < rem) {
                ins.mnemonic = "MOV";
                ins.operands = std::string(REG8[op - 0xB0])
                               + ", " + hex_byte(p[pos++]);
            }
        }

        // ---- MOV r/m32, r32 (0x89) ----
        else if (op == 0x89) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, true, false);
            pos += skip;
            ins.mnemonic = "MOV";
            ins.operands = modrm_str;
        }

        // ---- MOV r32, r/m32 (0x8B) ----
        else if (op == 0x8B) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, true, true);
            pos += skip;
            ins.mnemonic = "MOV";
            ins.operands = modrm_str;
        }

        // ---- MOV r/m8, r8 (0x88) ----
        else if (op == 0x88) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, false, false);
            pos += skip;
            ins.mnemonic = "MOV";
            ins.operands = modrm_str;
        }

        // ---- MOV r8, r/m8 (0x8A) ----
        else if (op == 0x8A) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, false, true);
            pos += skip;
            ins.mnemonic = "MOV";
            ins.operands = modrm_str;
        }

        // ---- LEA r32, m (0x8D) ----
        else if (op == 0x8D) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, true, true);
            pos += skip;
            ins.mnemonic = "LEA";
            ins.operands = modrm_str;
        }

        // ---- ADD / OR / ADC / SBB / AND / SUB / XOR / CMP r/m, imm8 (0x83) ----
        else if (op == 0x83) {
            if (pos < rem) {
                u8 modrm_b = p[pos];
                int reg = (modrm_b >> 3) & 7;
                static const char* ops83[] = {
                    "ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"
                };
                auto [modrm_str, skip] = decode_modrm(
                    p, pos, rem, true, false);
                pos += skip;
                i8 imm8 = static_cast<i8>(p[pos++]);
                ins.mnemonic = ops83[reg];
                ins.operands = modrm_str.substr(
                    modrm_str.find(',') + 2)
                    + ", " + std::to_string(imm8);
                (void)modrm_b;
            }
        }

        // ---- ADD r/m32, r32 (0x01) ----
        else if (op == 0x01) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,false);
            pos += skip; ins.mnemonic = "ADD"; ins.operands = s;
        }
        // ---- ADD r32, r/m32 (0x03) ----
        else if (op == 0x03) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,true);
            pos += skip; ins.mnemonic = "ADD"; ins.operands = s;
        }
        // ---- SUB r/m32, r32 (0x29) ----
        else if (op == 0x29) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,false);
            pos += skip; ins.mnemonic = "SUB"; ins.operands = s;
        }
        // ---- SUB r32, r/m32 (0x2B) ----
        else if (op == 0x2B) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,true);
            pos += skip; ins.mnemonic = "SUB"; ins.operands = s;
        }
        // ---- XOR r/m32, r32 (0x31) ----
        else if (op == 0x31) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,false);
            pos += skip; ins.mnemonic = "XOR"; ins.operands = s;
        }
        // ---- XOR r32, r/m32 (0x33) ----
        else if (op == 0x33) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,true);
            pos += skip; ins.mnemonic = "XOR"; ins.operands = s;
        }
        // ---- AND r/m32, r32 (0x21) ----
        else if (op == 0x21) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,false);
            pos += skip; ins.mnemonic = "AND"; ins.operands = s;
        }
        // ---- CMP r/m32, r32 (0x39) ----
        else if (op == 0x39) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,false);
            pos += skip; ins.mnemonic = "CMP"; ins.operands = s;
        }
        // ---- CMP r32, r/m32 (0x3B) ----
        else if (op == 0x3B) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,true);
            pos += skip; ins.mnemonic = "CMP"; ins.operands = s;
        }

        // ---- CMP r/m32, imm32 (0x81 /7) ----
        else if (op == 0x81) {
            if (pos < rem) {
                u8 modrm_b = p[pos];
                int reg = (modrm_b >> 3) & 7;
                static const char* ops81[] = {
                    "ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"
                };
                auto [modrm_str, skip] = decode_modrm(
                    p, pos, rem, true, false);
                pos += skip;
                u32 imm32 = 0;
                if (pos + 3 < rem) {
                    imm32 = read_u32(p + pos); pos += 4;
                }
                ins.mnemonic = ops81[reg];
                ins.operands = "..., 0x" + hex32(imm32);
                (void)modrm_str;
            }
        }

        // ---- TEST r/m32, r32 (0x85) ----
        else if (op == 0x85) {
            auto [s, skip] = decode_modrm(p,pos,rem,true,false);
            pos += skip; ins.mnemonic = "TEST"; ins.operands = s;
        }

        // ---- INC r32 (0x40-0x47) ----
        else if (op >= 0x40 && op <= 0x47) {
            ins.mnemonic = "INC";
            ins.operands = REG32[op - 0x40];
        }

        // ---- DEC r32 (0x48-0x4F) ----
        else if (op >= 0x48 && op <= 0x4F) {
            ins.mnemonic = "DEC";
            ins.operands = REG32[op - 0x48];
        }

        // ---- XCHG eax, r32 (0x91-0x97) ----
        else if (op >= 0x91 && op <= 0x97) {
            ins.mnemonic = "XCHG";
            ins.operands = std::string("eax, ")
                           + REG32[op - 0x90];
        }

        // ---- CDQ (0x99) ----
        else if (op == 0x99) { ins.mnemonic = "CDQ"; }

        // ---- IMUL r32, r/m32 (0x0F AF) ----
        // handled in two-byte section below

        // ---- MUL r/m32 (0xF7 /4) ----
        else if (op == 0xF7) {
            if (pos < rem) {
                u8 modrm_b = p[pos];
                int reg = (modrm_b >> 3) & 7;
                static const char* opsF7[] = {
                    "TEST","???","NOT","NEG","MUL","IMUL","DIV","IDIV"
                };
                auto [modrm_str, skip] = decode_modrm(
                    p, pos, rem, true, false);
                pos += skip;
                ins.mnemonic = opsF7[reg];
                ins.operands = modrm_str.substr(
                    modrm_str.find(',') != std::string::npos
                    ? modrm_str.find(',') + 2 : 0);
                (void)modrm_b;
            }
        }

        // ---- CALL rel32 (0xE8) ----
        else if (op == 0xE8) {
            if (pos + 3 < rem) {
                i32 rel = static_cast<i32>(read_u32(p + pos));
                pos += 4;
                u32 tgt = offset + pos + static_cast<u32>(rel);
                ins.mnemonic     = "CALL";
                ins.operands     = "0x" + hex32(tgt);
                ins.cat          = InstrCat::CALL;
                ins.has_target   = true;
                ins.target       = tgt;
                ins.has_fallthrough = true;
            }
        }

        // ---- CALL r/m32 (0xFF /2) ----
        else if (op == 0xFF) {
            if (pos < rem) {
                u8 modrm_b = p[pos];
                int reg = (modrm_b >> 3) & 7;
                auto [modrm_str, skip] = decode_modrm(
                    p, pos, rem, true, false);
                pos += skip;
                if (reg == 2) {
                    ins.mnemonic = "CALL";
                    ins.operands = modrm_str;
                    ins.cat      = InstrCat::CALL;
                    ins.has_fallthrough = true;
                } else if (reg == 4) {
                    // JMP r/m32
                    ins.mnemonic     = "JMP";
                    ins.operands     = modrm_str;
                    ins.cat          = InstrCat::UNCOND_JMP;
                    ins.has_target   = false; // indirect
                    ins.has_fallthrough = false;
                } else if (reg == 6) {
                    ins.mnemonic = "PUSH";
                    ins.operands = modrm_str;
                } else {
                    ins.mnemonic = "FF/" + std::to_string(reg);
                }
            }
        }

        // ---- RET (0xC3) ----
        else if (op == 0xC3) {
            ins.mnemonic        = "RET";
            ins.cat             = InstrCat::RET;
            ins.has_fallthrough = false;
        }

        // ---- RETN imm16 (0xC2) ----
        else if (op == 0xC2) {
            if (pos + 1 < rem) {
                u16 imm = read_u16(p + pos); pos += 2;
                ins.mnemonic = "RETN";
                ins.operands = std::to_string(imm);
                ins.cat      = InstrCat::RET;
                ins.has_fallthrough = false;
            }
        }

        // ---- RETF (0xCB) ----
        else if (op == 0xCB) {
            ins.mnemonic        = "RETF";
            ins.cat             = InstrCat::RET;
            ins.has_fallthrough = false;
        }

        // ---- INT n (0xCD) ----
        else if (op == 0xCD) {
            if (pos < rem) {
                u8 n = p[pos++];
                ins.mnemonic = "INT";
                ins.operands = "0x" + hex_byte(n);
                ins.cat      = InstrCat::INT;
                ins.has_fallthrough = false;
            }
        }

        // ---- INT3 (0xCC) ----
        else if (op == 0xCC) {
            ins.mnemonic        = "INT3";
            ins.cat             = InstrCat::INT;
            ins.has_fallthrough = false;
        }

        // ---- HLT (0xF4) ----
        else if (op == 0xF4) {
            ins.mnemonic        = "HLT";
            ins.cat             = InstrCat::HLT;
            ins.has_fallthrough = false;
        }

        // ---- JMP rel8 (0xEB) ----
        else if (op == 0xEB) {
            if (pos < rem) {
                i8 rel = static_cast<i8>(p[pos++]);
                u32 tgt = offset + pos + static_cast<u32>(rel);
                ins.mnemonic        = "JMP";
                ins.operands        = "short 0x" + hex32(tgt);
                ins.cat             = InstrCat::UNCOND_JMP;
                ins.has_target      = true;
                ins.target          = tgt;
                ins.has_fallthrough = false;
            }
        }

        // ---- JMP rel32 (0xE9) ----
        else if (op == 0xE9) {
            if (pos + 3 < rem) {
                i32 rel = static_cast<i32>(read_u32(p + pos));
                pos += 4;
                u32 tgt = offset + pos + static_cast<u32>(rel);
                ins.mnemonic        = "JMP";
                ins.operands        = "0x" + hex32(tgt);
                ins.cat             = InstrCat::UNCOND_JMP;
                ins.has_target      = true;
                ins.target          = tgt;
                ins.has_fallthrough = false;
            }
        }

        // ---- Jcc rel8 (0x70-0x7F) ----
        else if (op >= 0x70 && op <= 0x7F) {
            if (pos < rem) {
                i8 rel = static_cast<i8>(p[pos++]);
                u32 tgt = offset + pos + static_cast<u32>(rel);
                ins.mnemonic        = jcc_mnemonic(op - 0x70);
                ins.operands        = "short 0x" + hex32(tgt);
                ins.cat             = InstrCat::COND_JMP;
                ins.has_target      = true;
                ins.target          = tgt;
                ins.has_fallthrough = true;
            }
        }

        // ---- LOOP / LOOPE / LOOPNE (0xE0-0xE2), JCXZ (0xE3) ----
        else if (op >= 0xE0 && op <= 0xE3) {
            if (pos < rem) {
                i8 rel = static_cast<i8>(p[pos++]);
                u32 tgt = offset + pos + static_cast<u32>(rel);
                static const char* lnames[] = {
                    "LOOPNE","LOOPE","LOOP","JCXZ"
                };
                ins.mnemonic        = lnames[op - 0xE0];
                ins.operands        = "0x" + hex32(tgt);
                ins.cat             = InstrCat::COND_JMP;
                ins.has_target      = true;
                ins.target          = tgt;
                ins.has_fallthrough = true;
            }
        }

        // ---- Two-byte opcode prefix 0x0F ----
        else if (op == 0x0F) {
            if (pos >= rem) {
                ins.mnemonic = "DB"; ins.operands = "0x0f";
                ins.cat = InstrCat::UNKNOWN;
            } else {
                u8 op2 = p[pos++];

                // Jcc rel32 (0x0F 80-0x0F 8F)
                if (op2 >= 0x80 && op2 <= 0x8F) {
                    if (pos + 3 < rem) {
                        i32 rel = static_cast<i32>(
                                      read_u32(p + pos));
                        pos += 4;
                        u32 tgt = offset + pos
                                  + static_cast<u32>(rel);
                        ins.mnemonic = jcc_mnemonic(op2 - 0x80);
                        ins.operands = "0x" + hex32(tgt);
                        ins.cat      = InstrCat::COND_JMP;
                        ins.has_target = true;
                        ins.target     = tgt;
                        ins.has_fallthrough = true;
                    }
                }
                // MOVZX r32, r/m8 (0x0F B6)
                else if (op2 == 0xB6) {
                    auto [s, sk] = decode_modrm(
                        p, pos, rem, false, true);
                    pos += sk;
                    ins.mnemonic = "MOVZX";
                    ins.operands = s;
                }
                // MOVZX r32, r/m16 (0x0F B7)
                else if (op2 == 0xB7) {
                    auto [s, sk] = decode_modrm(
                        p, pos, rem, true, true);
                    pos += sk;
                    ins.mnemonic = "MOVZX";
                    ins.operands = s;
                }
                // MOVSX r32, r/m8 (0x0F BE)
                else if (op2 == 0xBE) {
                    auto [s, sk] = decode_modrm(
                        p, pos, rem, false, true);
                    pos += sk;
                    ins.mnemonic = "MOVSX";
                    ins.operands = s;
                }
                // IMUL r32, r/m32 (0x0F AF)
                else if (op2 == 0xAF) {
                    auto [s, sk] = decode_modrm(
                        p, pos, rem, true, true);
                    pos += sk;
                    ins.mnemonic = "IMUL";
                    ins.operands = s;
                }
                // SETCC r/m8 (0x0F 90-9F)
                else if (op2 >= 0x90 && op2 <= 0x9F) {
                    auto [s, sk] = decode_modrm(
                        p, pos, rem, false, false);
                    pos += sk;
                    static const char* setcc[] = {
                        "SETO","SETNO","SETB","SETNB",
                        "SETZ","SETNZ","SETBE","SETNBE",
                        "SETS","SETNS","SETP","SETNP",
                        "SETL","SETNL","SETLE","SETNLE"
                    };
                    ins.mnemonic = setcc[op2 - 0x90];
                    ins.operands = s;
                }
                // PUSH FS (0x0F A0)
                else if (op2 == 0xA0) {
                    ins.mnemonic = "PUSH"; ins.operands = "fs";
                }
                // POP FS (0x0F A1)
                else if (op2 == 0xA1) {
                    ins.mnemonic = "POP"; ins.operands = "fs";
                }
                // CPUID (0x0F A2)
                else if (op2 == 0xA2) { ins.mnemonic = "CPUID"; }
                // SHL/SHR/SAR r/m32, 1 (0xD1)
                else if (op2 == 0xBC) {
                    auto [s, sk] = decode_modrm(
                        p, pos, rem, true, true);
                    pos += sk;
                    ins.mnemonic = "BSF";
                    ins.operands = s;
                }
                else {
                    ins.mnemonic = "0F " + hex_byte(op2);
                    ins.cat      = InstrCat::UNKNOWN;
                }
            }
        }

        // ---- SHL/SHR/SAR r/m32, CL or imm8 (0xD1 / 0xC1) ----
        else if (op == 0xD1 || op == 0xC1 || op == 0xD3) {
            if (pos < rem) {
                u8 modrm_b = p[pos];
                int reg = (modrm_b >> 3) & 7;
                static const char* shfops[] = {
                    "ROL","ROR","RCL","RCR","SHL","SHR","SAL","SAR"
                };
                auto [modrm_str, skip] = decode_modrm(
                    p, pos, rem, true, false);
                pos += skip;
                ins.mnemonic = shfops[reg];
                std::string rm = modrm_str.substr(
                    modrm_str.find(',') != std::string::npos
                    ? modrm_str.find(',') + 2 : 0);
                if (op == 0xC1) {
                    u8 imm = pos < rem ? p[pos++] : 1;
                    ins.operands = rm + ", " + std::to_string(imm);
                } else if (op == 0xD3) {
                    ins.operands = rm + ", cl";
                } else {
                    ins.operands = rm + ", 1";
                }
                (void)modrm_b;
            }
        }

        // ---- LEAVE (0xC9) ----
        else if (op == 0xC9) { ins.mnemonic = "LEAVE"; }

        // ---- ENTER (0xC8) ----
        else if (op == 0xC8) {
            if (pos + 2 < rem) {
                u16 sz  = read_u16(p + pos); pos += 2;
                u8  lev = p[pos++];
                ins.mnemonic = "ENTER";
                ins.operands = std::to_string(sz) + ", "
                               + std::to_string(lev);
            }
        }

        // ---- PUSHAD (0x60) / POPAD (0x61) ----
        else if (op == 0x60) { ins.mnemonic = "PUSHAD"; }
        else if (op == 0x61) { ins.mnemonic = "POPAD"; }

        // ---- PUSHFD (0x9C) / POPFD (0x9D) ----
        else if (op == 0x9C) { ins.mnemonic = "PUSHFD"; }
        else if (op == 0x9D) { ins.mnemonic = "POPFD"; }

        // ---- STD (0xFD) / CLD (0xFC) / STI (0xFB) / CLI (0xFA) ----
        else if (op == 0xFC) { ins.mnemonic = "CLD"; }
        else if (op == 0xFD) { ins.mnemonic = "STD"; }
        else if (op == 0xFA) { ins.mnemonic = "CLI"; }
        else if (op == 0xFB) { ins.mnemonic = "STI"; }

        // ---- MOV segreg (0x8E) ----
        else if (op == 0x8E) {
            if (pos < rem) {
                u8 modrm_b = p[pos++];
                int reg = (modrm_b >> 3) & 7;
                ins.mnemonic = "MOV";
                ins.operands = std::string(SREG[reg])
                               + ", ...";
            }
        }

        // ---- XCHG r/m32, r32 (0x87) ----
        else if (op == 0x87) {
            auto [s, sk] = decode_modrm(p,pos,rem,true,false);
            pos += sk; ins.mnemonic = "XCHG"; ins.operands = s;
        }

        // ---- MOV m, imm32 (0xC7 /0) ----
        else if (op == 0xC7) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, true, false);
            pos += skip;
            u32 imm = 0;
            if (pos + 3 < rem) { imm = read_u32(p+pos); pos+=4; }
            ins.mnemonic = "MOV";
            ins.operands = "..., 0x" + hex32(imm);
        }

        // ---- MOV m8, imm8 (0xC6 /0) ----
        else if (op == 0xC6) {
            auto [modrm_str, skip] = decode_modrm(
                p, pos, rem, false, false);
            pos += skip;
            u8 imm = pos < rem ? p[pos++] : 0;
            ins.mnemonic = "MOV";
            ins.operands = "..., " + hex_byte(imm);
        }

        // ---- ADD/etc eax, imm32 (0x05, 0x2D, etc.) ----
        else if (op == 0x05) {
            if (pos+3<rem){ u32 i=read_u32(p+pos);pos+=4;
            ins.mnemonic="ADD";ins.operands="eax,0x"+hex32(i);}
        }
        else if (op == 0x2D) {
            if (pos+3<rem){ u32 i=read_u32(p+pos);pos+=4;
            ins.mnemonic="SUB";ins.operands="eax,0x"+hex32(i);}
        }
        else if (op == 0x35) {
            if (pos+3<rem){ u32 i=read_u32(p+pos);pos+=4;
            ins.mnemonic="XOR";ins.operands="eax,0x"+hex32(i);}
        }
        else if (op == 0x3D) {
            if (pos+3<rem){ u32 i=read_u32(p+pos);pos+=4;
            ins.mnemonic="CMP";ins.operands="eax,0x"+hex32(i);}
        }

        // ---- STOS / MOVS / SCAS / LODS (0xAB/AA/A5/A4...) ----
        else if (op==0xAB){ins.mnemonic="STOSD";}
        else if (op==0xAA){ins.mnemonic="STOSB";}
        else if (op==0xA5){ins.mnemonic="MOVSD";}
        else if (op==0xA4){ins.mnemonic="MOVSB";}
        else if (op==0xAF){ins.mnemonic="SCASD";}
        else if (op==0xAE){ins.mnemonic="SCASB";}
        else if (op==0xAD){ins.mnemonic="LODSD";}
        else if (op==0xAC){ins.mnemonic="LODSB";}

        // ---- OR r/m32, r32 (0x09) ----
        else if (op==0x09){
            auto[s,sk]=decode_modrm(p,pos,rem,true,false);
            pos+=sk;ins.mnemonic="OR";ins.operands=s;
        }

        // ---- Unknown / DB ----
        else {
            ins.mnemonic = "DB";
            ins.operands = hex_byte(op);
            ins.cat      = InstrCat::UNKNOWN;
        }

        // ---- Finalize length and operand size prefix note ----
        ins.len = static_cast<u8>(pos);
        if (opsz_override && ins.mnemonic == "MOV")
            ins.mnemonic += "W"; // 16-bit override hint

        return ins;
    }

    // ============================================================
    // DISASSEMBLE ENTIRE BUFFER
    // ============================================================
    static std::vector<Instr> disassemble(
            const u8* buf, size_t len, u32 base = 0) {
        std::vector<Instr> instrs;
        u32 offset = 0;
        while (offset < static_cast<u32>(len)) {
            Instr ins = decode(buf, len, offset);
            ins.offset += base;
            if (ins.has_target) ins.target += base;
            if (ins.len == 0) ins.len = 1;
            instrs.push_back(ins);
            offset += ins.len;
        }
        return instrs;
    }

private:
    // ---- Read little-endian integers ----
    static u16 read_u16(const u8* p) {
        return static_cast<u16>(p[0]) |
               (static_cast<u16>(p[1]) << 8);
    }
    static u32 read_u32(const u8* p) {
        return static_cast<u32>(p[0])
             | (static_cast<u32>(p[1]) <<  8)
             | (static_cast<u32>(p[2]) << 16)
             | (static_cast<u32>(p[3]) << 24);
    }

    // ---- Hex formatting helpers ----
    static std::string hex_byte(u8 v) {
        std::ostringstream o;
        o << std::hex << std::setw(2)
          << std::setfill('0') << static_cast<int>(v);
        return o.str();
    }
    static std::string hex32(u32 v) {
        std::ostringstream o;
        o << std::hex << std::setw(8)
          << std::setfill('0') << v;
        return o.str();
    }

    // ---- Jcc mnemonic table ----
    static const char* jcc_mnemonic(int cond) {
        static const char* names[16] = {
            "JO","JNO","JB","JNB","JZ","JNZ","JBE","JNBE",
            "JS","JNS","JP","JNP","JL","JNL","JLE","JNLE"
        };
        return (cond >= 0 && cond < 16) ? names[cond] : "J??";
    }

    // ---- ModRM decoder ----
    // Returns {operand_string, bytes_consumed}
    // is32: true = 32-bit operand, false = 8-bit
    // reversed: true = reg is destination, false = rm is dest
    static std::pair<std::string, size_t>
    decode_modrm(const u8* p, size_t pos,
                  size_t rem, bool is32, bool reversed) {
        if (pos >= rem) return {"???", 0};

        u8 modrm = p[pos];
        int mod  = (modrm >> 6) & 3;
        int reg  = (modrm >> 3) & 7;
        int rm   = modrm & 7;
        size_t consumed = 1;

        auto reg_name = [&](int r) -> std::string {
            return is32 ? REG32[r] : REG8[r];
        };

        std::string rm_str;

        if (mod == 3) {
            // Register operand
            rm_str = reg_name(rm);
        } else {
            // Memory operand
            std::string base_str, disp_str;
            int disp_bytes = 0;

            if (mod == 0 && rm == 5) {
                // Special: [disp32]
                if (pos + 4 < rem) {
                    u32 d = read_u32(p + pos + 1);
                    consumed += 4;
                    rm_str = "[0x" + hex32(d) + "]";
                    goto done;
                }
            }

            if (rm == 4) {
                // SIB byte follows
                if (pos + consumed < rem) {
                    u8 sib = p[pos + consumed++];
                    int scale = 1 << ((sib >> 6) & 3);
                    int idx   = (sib >> 3) & 7;
                    int base2 = sib & 7;

                    if (base2 != 5 || mod != 0)
                        base_str = REG32[base2];
                    if (idx != 4) {
                        if (!base_str.empty()) base_str += "+";
                        base_str += REG32[idx];
                        if (scale > 1)
                            base_str += "*"
                                + std::to_string(scale);
                    }
                }
            } else {
                base_str = REG32[rm];
            }

            if (mod == 1) disp_bytes = 1;
            else if (mod == 2) disp_bytes = 4;

            if (disp_bytes > 0
                && pos + consumed + disp_bytes <= rem) {
                if (disp_bytes == 1) {
                    i8 d = static_cast<i8>(
                               p[pos + consumed]);
                    consumed += 1;
                    if (d >= 0)
                        disp_str = "+" + std::to_string(d);
                    else
                        disp_str = std::to_string(d);
                } else {
                    i32 d = static_cast<i32>(
                        read_u32(p + pos + consumed));
                    consumed += 4;
                    if (d >= 0)
                        disp_str = "+0x" + hex32(
                            static_cast<u32>(d));
                    else
                        disp_str = "-0x" + hex32(
                            static_cast<u32>(-d));
                }
            }

            rm_str = "[" + base_str + disp_str + "]";
        }

        done:
        std::string reg_str = reg_name(reg);
        std::string result;
        if (reversed)
            result = reg_str + ", " + rm_str;
        else
            result = rm_str  + ", " + reg_str;

        return {result, consumed};
    }
};

// ============================================================
// ============================================================
//   SECTION 2 — BASIC BLOCK BUILDER
// ============================================================
// ============================================================
// A basic block is a maximal sequence of instructions with
// exactly one entry (the first instruction is a leader) and
// one exit (the last instruction is a branch or fall-through).
//
// Leader identification rules:
//   1. The first instruction of the function
//   2. Any instruction that is a branch target
//   3. The instruction immediately following a branch
// ============================================================

struct BasicBlock {
    u32                  id          = 0;
    u32                  start_off   = 0;   // offset of first instr
    u32                  end_off     = 0;   // offset AFTER last instr
    std::vector<size_t>  instr_idx;         // indices into instr array
    std::vector<u32>     succs;             // successor block IDs
    std::vector<u32>     preds;             // predecessor block IDs
    bool                 is_entry    = false;
    bool                 is_exit     = false;
    bool                 reachable   = false;
    bool                 is_loop_header = false;
    bool                 is_dead_code   = false;

    // Analysis results
    int  dom_parent = -1;            // dominator tree parent
    int  rpo_num    = -1;            // reverse post-order number
    std::string label() const {
        std::ostringstream o;
        o << "BB" << id << "_" << std::hex
          << std::setw(4) << std::setfill('0') << start_off;
        return o.str();
    }
};

// ============================================================
// ============================================================
//   SECTION 3 — CFG CONSTRUCTION
// ============================================================
// ============================================================

class CFG {
public:
    std::vector<Instr>      instrs;      // all decoded instructions
    std::vector<BasicBlock> blocks;      // basic blocks
    u32                     base_addr;   // load address

    CFG() : base_addr(0) {}

    // --------------------------------------------------------
    // BUILD CFG FROM BYTE BUFFER
    // --------------------------------------------------------
    void build(const u8* buf, size_t len, u32 base = 0) {
        base_addr = base;
        blocks.clear();
        instrs.clear();

        // Step 1: Disassemble all bytes
        instrs = X86Decoder::disassemble(buf, len, base);

        if (instrs.empty()) return;

        // Step 2: Identify leaders
        std::set<u32> leaders;
        leaders.insert(instrs[0].offset); // first instr is always a leader

        for (size_t i = 0; i < instrs.size(); i++) {
            const Instr& ins = instrs[i];

            // Branch target is a leader
            if (ins.has_target &&
                ins.target >= base &&
                ins.target < base + static_cast<u32>(len)) {
                leaders.insert(ins.target);
            }

            // Instruction after a branch is a leader
            if ((ins.cat == InstrCat::UNCOND_JMP ||
                 ins.cat == InstrCat::COND_JMP   ||
                 ins.cat == InstrCat::CALL        ||
                 ins.cat == InstrCat::RET         ||
                 ins.cat == InstrCat::INT         ||
                 ins.cat == InstrCat::HLT)
                && i + 1 < instrs.size()) {
                leaders.insert(instrs[i + 1].offset);
            }
        }

        // Step 3: Partition instructions into basic blocks
        std::map<u32, u32> offset_to_block; // offset → block ID

        {
            u32 blk_id = 0;
            BasicBlock current;
            current.id        = blk_id;
            current.start_off = instrs[0].offset;
            current.is_entry  = true;

            for (size_t i = 0; i < instrs.size(); i++) {
                const Instr& ins = instrs[i];

                // New leader starts a new block
                if (i > 0 && leaders.count(ins.offset)) {
                    current.end_off = ins.offset;
                    blocks.push_back(current);
                    blk_id++;
                    current = BasicBlock();
                    current.id        = blk_id;
                    current.start_off = ins.offset;
                }

                offset_to_block[ins.offset] = blk_id;
                current.instr_idx.push_back(i);
            }

            // Finalize last block
            const Instr& last = instrs.back();
            current.end_off = last.offset + last.len;
            blocks.push_back(current);
        }

        // Step 4: Resolve edges between blocks
        for (auto& blk : blocks) {
            if (blk.instr_idx.empty()) continue;

            const Instr& last_ins =
                instrs[blk.instr_idx.back()];

            // Determine successors based on last instruction
            bool is_terminal =
                last_ins.cat == InstrCat::RET ||
                last_ins.cat == InstrCat::INT ||
                last_ins.cat == InstrCat::HLT;

            if (is_terminal) {
                blk.is_exit = true;
            }

            // Fall-through edge
            if (last_ins.has_fallthrough && !is_terminal) {
                u32 fall_off = last_ins.offset + last_ins.len;
                auto it = offset_to_block.find(fall_off);
                if (it != offset_to_block.end()) {
                    blk.succs.push_back(it->second);
                }
            }

            // Taken branch edge
            if (last_ins.has_target) {
                auto it = offset_to_block.find(
                    last_ins.target - base_addr + base_addr);
                // Correct: target is already absolute
                if (it == offset_to_block.end()) {
                    // Try direct lookup
                    it = offset_to_block.find(last_ins.target);
                }
                if (it != offset_to_block.end()) {
                    u32 tgt_id = it->second;
                    // Avoid duplicate
                    if (std::find(blk.succs.begin(),
                                   blk.succs.end(),
                                   tgt_id) == blk.succs.end())
                        blk.succs.push_back(tgt_id);
                }
            }
        }

        // Step 5: Build predecessor lists
        for (auto& blk : blocks) {
            for (u32 succ_id : blk.succs) {
                if (succ_id < blocks.size())
                    blocks[succ_id].preds.push_back(blk.id);
            }
        }

        // Step 6: Mark reachable blocks via BFS from entry
        mark_reachable();

        // Step 7: Compute reverse post-order
        compute_rpo();

        // Step 8: Compute dominator tree
        compute_dominators();
    }

    // --------------------------------------------------------
    // MARK REACHABLE BLOCKS (BFS from block 0)
    // --------------------------------------------------------
    void mark_reachable() {
        if (blocks.empty()) return;
        std::queue<u32> q;
        q.push(0);
        blocks[0].reachable = true;
        while (!q.empty()) {
            u32 id = q.front(); q.pop();
            for (u32 s : blocks[id].succs) {
                if (s < blocks.size() &&
                    !blocks[s].reachable) {
                    blocks[s].reachable = true;
                    q.push(s);
                }
            }
        }
        for (auto& b : blocks)
            if (!b.reachable) b.is_dead_code = true;
    }

    // --------------------------------------------------------
    // REVERSE POST-ORDER TRAVERSAL (DFS-based)
    // RPO is the ordering used by dominance algorithms.
    // --------------------------------------------------------
    void compute_rpo() {
        if (blocks.empty()) return;
        std::vector<bool> visited(blocks.size(), false);
        std::vector<u32>  post_order;

        std::function<void(u32)> dfs = [&](u32 id) {
            visited[id] = true;
            for (u32 s : blocks[id].succs) {
                if (s < blocks.size() && !visited[s])
                    dfs(s);
            }
            post_order.push_back(id);
        };

        dfs(0);

        // Reverse post order
        int n = static_cast<int>(post_order.size());
        for (int i = 0; i < n; i++) {
            u32 blk_id = post_order[n - 1 - i];
            if (blk_id < blocks.size())
                blocks[blk_id].rpo_num = i;
        }
    }

    // --------------------------------------------------------
    // DOMINATOR TREE — Cooper et al. simple iterative algorithm
    // idom[b] = immediate dominator of block b
    // Block 0 dominates all others.
    // idom[b] = LCA(idom[p1], idom[p2], ...) for all preds p
    // --------------------------------------------------------
    void compute_dominators() {
        size_t n = blocks.size();
        if (n == 0) return;

        std::vector<int> idom(n, -1);
        idom[0] = 0;

        // Build RPO-indexed array for fast lookup
        std::vector<int> rpo_order(n, -1);
        for (size_t i = 0; i < n; i++)
            if (blocks[i].rpo_num >= 0)
                rpo_order[blocks[i].rpo_num] =
                    static_cast<int>(i);

        auto intersect = [&](int b1, int b2) -> int {
            while (b1 != b2) {
                while (blocks[b1].rpo_num >
                       blocks[b2].rpo_num)
                    b1 = idom[b1];
                while (blocks[b2].rpo_num >
                       blocks[b1].rpo_num)
                    b2 = idom[b2];
            }
            return b1;
        };

        bool changed = true;
        while (changed) {
            changed = false;
            // Process in RPO (skip entry block 0)
            for (int rpo = 1; rpo < static_cast<int>(n); rpo++) {
                int b = rpo_order[rpo];
                if (b < 0 || static_cast<size_t>(b) >= n)
                    continue;

                int new_idom = -1;
                for (u32 p : blocks[b].preds) {
                    if (idom[p] == -1) continue;
                    if (new_idom == -1)
                        new_idom = static_cast<int>(p);
                    else
                        new_idom = intersect(
                            new_idom, static_cast<int>(p));
                }

                if (new_idom != -1 && new_idom != idom[b]) {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        for (size_t i = 0; i < n; i++)
            blocks[i].dom_parent = idom[i];
    }

    // --------------------------------------------------------
    // DETECT LOOP HEADERS (back edges in DFS)
    // A back edge u → v exists when v dominates u.
    // v is then a loop header.
    // --------------------------------------------------------
    void detect_loops() {
        size_t n = blocks.size();
        std::vector<bool> visited(n, false);
        std::vector<bool> in_stack(n, false);

        std::function<void(u32)> dfs = [&](u32 id) {
            visited[id]  = true;
            in_stack[id] = true;
            for (u32 s : blocks[id].succs) {
                if (s >= n) continue;
                if (in_stack[s]) {
                    // Back edge id → s: s is a loop header
                    blocks[s].is_loop_header = true;
                } else if (!visited[s]) {
                    dfs(s);
                }
            }
            in_stack[id] = false;
        };

        if (!blocks.empty()) dfs(0);
    }

    // --------------------------------------------------------
    // CYCLOMATIC COMPLEXITY (McCabe)
    // M = E - N + 2P
    // E = number of edges, N = number of nodes (blocks),
    // P = number of connected components (1 for one function)
    // Equivalent formula: M = number of decision points + 1
    // --------------------------------------------------------
    int cyclomatic_complexity() const {
        int E = 0;
        int N = static_cast<int>(blocks.size());
        for (const auto& b : blocks)
            E += static_cast<int>(b.succs.size());
        return E - N + 2;
    }

    // --------------------------------------------------------
    // COUNT BACK EDGES (loops)
    // --------------------------------------------------------
    int back_edge_count() const {
        int count = 0;
        for (const auto& b : blocks)
            for (u32 s : b.succs)
                if (s < blocks.size() &&
                    blocks[s].rpo_num <= b.rpo_num &&
                    blocks[s].rpo_num >= 0)
                    count++;
        return count;
    }
};

// ============================================================
// ============================================================
//   SECTION 4 — MALWARE PATTERN DETECTOR
// ============================================================
// ============================================================

struct MalwareReport {
    bool has_infinite_loop     = false;
    bool has_dead_code         = false;
    bool has_indirect_jmp      = false;
    bool has_self_ref_loop     = false; // block jumps to itself
    bool high_cyclomatic       = false; // > 10 suggests obfuscation
    bool many_unconditional    = false; // > 30% JMP → obfuscator
    bool has_int3_nop_sled     = false; // CC CC CC patterns
    bool suspicious_cfg_shape  = false; // many dead + few reachable

    int  dead_block_count      = 0;
    int  loop_count            = 0;
    int  cyclomatic            = 0;
    int  obfuscation_score     = 0;     // 0-100
    std::vector<std::string> findings;
};

class MalwareDetector {
public:
    static MalwareReport analyse(
            const CFG& cfg,
            const std::vector<u8>& raw_bytes) {
        MalwareReport rep;
        rep.cyclomatic = cfg.cyclomatic_complexity();

        // ---- Dead code ----
        for (const auto& b : cfg.blocks) {
            if (b.is_dead_code) {
                rep.has_dead_code = true;
                rep.dead_block_count++;
            }
        }

        // ---- Self-referential loops ----
        for (const auto& b : cfg.blocks) {
            for (u32 s : b.succs) {
                if (s == b.id) {
                    rep.has_self_ref_loop = true;
                    rep.has_infinite_loop = true;
                    rep.findings.push_back(
                        "BB" + std::to_string(b.id)
                        + " jumps to itself (infinite loop)");
                }
            }
        }

        // ---- Loop count ----
        rep.loop_count = cfg.back_edge_count();
        if (rep.loop_count > 0)
            rep.has_infinite_loop |=
                (rep.loop_count > 3);

        // ---- Indirect jumps ----
        for (const auto& ins : cfg.instrs) {
            if (ins.cat == InstrCat::UNCOND_JMP &&
                !ins.has_target) {
                rep.has_indirect_jmp = true;
                rep.findings.push_back(
                    "0x" + std::to_string(ins.offset)
                    + ": Indirect JMP (obfuscation / "
                      "vtable dispatch)");
            }
        }

        // ---- Cyclomatic complexity ----
        if (rep.cyclomatic > 10) {
            rep.high_cyclomatic = true;
            rep.findings.push_back(
                "High cyclomatic complexity: "
                + std::to_string(rep.cyclomatic)
                + " (>10 suggests obfuscation)");
        }

        // ---- Unconditional JMP ratio ----
        int jmp_count = 0;
        for (const auto& ins : cfg.instrs)
            if (ins.cat == InstrCat::UNCOND_JMP)
                jmp_count++;
        if (!cfg.instrs.empty()) {
            double ratio = static_cast<double>(jmp_count)
                           / cfg.instrs.size();
            if (ratio > 0.20) {
                rep.many_unconditional = true;
                rep.findings.push_back(
                    "High JMP ratio: "
                    + std::to_string(
                        static_cast<int>(ratio * 100))
                    + "% of instructions are JMPs");
            }
        }

        // ---- INT3 / NOP sled detection ----
        int cc_run = 0, nop_run = 0, max_cc = 0, max_nop = 0;
        for (u8 b : raw_bytes) {
            if (b == 0xCC) { cc_run++; nop_run = 0; }
            else if (b == 0x90) { nop_run++; cc_run = 0; }
            else { cc_run = 0; nop_run = 0; }
            max_cc  = std::max(max_cc, cc_run);
            max_nop = std::max(max_nop, nop_run);
        }
        if (max_cc >= 4) {
            rep.has_int3_nop_sled = true;
            rep.findings.push_back(
                "INT3 sled detected: "
                + std::to_string(max_cc)
                + " consecutive 0xCC bytes");
        }
        if (max_nop >= 8) {
            rep.has_int3_nop_sled = true;
            rep.findings.push_back(
                "NOP sled detected: "
                + std::to_string(max_nop)
                + " consecutive 0x90 bytes");
        }

        // ---- Suspicious CFG shape ----
        size_t reachable = 0;
        for (const auto& b : cfg.blocks)
            if (b.reachable) reachable++;
        if (cfg.blocks.size() > 2 &&
            reachable < cfg.blocks.size() / 2) {
            rep.suspicious_cfg_shape = true;
            rep.findings.push_back(
                "Suspicious CFG: only "
                + std::to_string(reachable) + "/"
                + std::to_string(cfg.blocks.size())
                + " blocks reachable");
        }

        // ---- Compute obfuscation score (0-100) ----
        int score = 0;
        if (rep.has_dead_code)       score += 15;
        if (rep.has_indirect_jmp)    score += 20;
        if (rep.has_self_ref_loop)   score += 20;
        if (rep.high_cyclomatic)     score += 20;
        if (rep.many_unconditional)  score += 15;
        if (rep.has_int3_nop_sled)   score += 5;
        if (rep.suspicious_cfg_shape)score += 25;
        rep.obfuscation_score = std::min(score, 100);

        return rep;
    }
};

// ============================================================
// ============================================================
//   SECTION 5 — DOT GRAPH EXPORTER
// ============================================================
// ============================================================

class DotExporter {
public:
    static void write(const CFG& cfg,
                       const MalwareReport& rep,
                       const std::string& filename) {
        std::ofstream f(filename);
        if (!f) {
            std::cerr << "[DOT] Cannot write to "
                      << filename << "\n";
            return;
        }

        f << "digraph CFG {\n";
        f << "  graph [rankdir=TB, splines=ortho,"
             " fontname=\"Courier\"];\n";
        f << "  node  [shape=record, fontname=\"Courier\","
             " fontsize=10];\n";
        f << "  edge  [fontname=\"Courier\", fontsize=9];\n\n";

        // Nodes
        for (const auto& blk : cfg.blocks) {
            std::string fill = "#E8E8FF"; // default: light blue
            if (!blk.reachable) fill  = "#FFE8E8"; // dead: red
            if (blk.is_entry)   fill  = "#E8FFE8"; // entry: green
            if (blk.is_exit)    fill  = "#FFFFD0"; // exit: yellow
            if (blk.is_loop_header) fill = "#FFE8C0"; // loop: orange

            // Build label showing instructions
            std::string lbl = blk.label() + "\\l";
            for (size_t idx : blk.instr_idx) {
                if (idx >= cfg.instrs.size()) continue;
                const Instr& ins = cfg.instrs[idx];
                std::ostringstream oss;
                oss << std::hex << std::setw(4)
                    << std::setfill('0') << ins.offset
                    << "  " << ins.mnemonic;
                if (!ins.operands.empty())
                    oss << " " << ins.operands;
                // Escape DOT special chars
                std::string line = oss.str();
                for (char& c : line) {
                    if (c == '<' || c == '>' || c == '|'
                        || c == '{' || c == '}')
                        c = ' ';
                }
                lbl += line + "\\l";
            }

            f << "  \"" << blk.label() << "\" [\n";
            f << "    label=\"" << lbl << "\"\n";
            f << "    style=filled fillcolor=\"" << fill << "\"\n";
            if (blk.is_dead_code)
                f << "    color=red\n";
            if (blk.is_loop_header)
                f << "    penwidth=2\n";
            f << "  ];\n";
        }

        f << "\n";

        // Edges
        for (const auto& blk : cfg.blocks) {
            const Instr* last = nullptr;
            if (!blk.instr_idx.empty()) {
                size_t li = blk.instr_idx.back();
                if (li < cfg.instrs.size())
                    last = &cfg.instrs[li];
            }

            for (size_t i = 0; i < blk.succs.size(); i++) {
                u32 sid = blk.succs[i];
                if (sid >= cfg.blocks.size()) continue;
                const BasicBlock& succ = cfg.blocks[sid];

                // Determine edge type
                bool is_taken    = false;
                bool is_fallthru = false;
                if (last &&
                    last->cat == InstrCat::COND_JMP) {
                    if (last->has_target &&
                        last->target == succ.start_off)
                        is_taken = true;
                    else
                        is_fallthru = true;
                }

                std::string edge_col = "#333333";
                std::string edge_lbl = "";
                if (is_taken) {
                    edge_col = "#CC4400";
                    edge_lbl = "T";
                } else if (is_fallthru) {
                    edge_col = "#0044CC";
                    edge_lbl = "F";
                }

                // Back edge (loop)
                if (succ.rpo_num >= 0 && blk.rpo_num >= 0 &&
                    succ.rpo_num <= blk.rpo_num) {
                    edge_col = "#AA00AA";
                    edge_lbl = "BACK";
                }

                f << "  \"" << blk.label()
                  << "\" -> \"" << succ.label() << "\"";
                f << " [color=\"" << edge_col << "\"";
                if (!edge_lbl.empty())
                    f << " label=\"" << edge_lbl << "\"";
                f << "];\n";
            }
        }

        // Legend
        f << "\n  subgraph cluster_legend {\n";
        f << "    label=\"Legend\";\n";
        f << "    style=dashed;\n";
        f << "    L1 [label=\"Entry\" style=filled "
             "fillcolor=\"#E8FFE8\"];\n";
        f << "    L2 [label=\"Exit\" style=filled "
             "fillcolor=\"#FFFFD0\"];\n";
        f << "    L3 [label=\"Loop header\" style=filled "
             "fillcolor=\"#FFE8C0\" penwidth=2];\n";
        f << "    L4 [label=\"Dead code\" style=filled "
             "fillcolor=\"#FFE8E8\" color=red];\n";
        f << "  }\n";

        f << "}\n";
        f.close();

        std::cout << "[DOT] Written to: " << filename << "\n";
        std::cout << "[DOT] Render with: "
                     "dot -Tpng " << filename
                  << " -o cfg.png\n";
    }
};

// ============================================================
// ============================================================
//   SECTION 6 — REPORT PRINTER
// ============================================================
// ============================================================

class Printer {
public:
    // Print full disassembly listing with annotations
    static void print_disassembly(const CFG& cfg) {
        hdr("DISASSEMBLY LISTING");
        u32 cur_block = 0xFFFFFFFF;

        for (size_t i = 0; i < cfg.instrs.size(); i++) {
            const Instr& ins = cfg.instrs[i];

            // Find which block this instruction belongs to
            for (const auto& blk : cfg.blocks) {
                if (!blk.instr_idx.empty() &&
                    blk.instr_idx[0] == i) {
                    if (cur_block != blk.id) {
                        cur_block = blk.id;
                        std::cout << "\n";
                        std::cout << "  ;"
                            << std::string(60, '-')
                            << "\n";
                        std::cout << "  ; " << blk.label();
                        if (blk.is_entry)
                            std::cout << " [ENTRY]";
                        if (blk.is_exit)
                            std::cout << " [EXIT]";
                        if (!blk.reachable)
                            std::cout << " [DEAD CODE]";
                        if (blk.is_loop_header)
                            std::cout << " [LOOP HEADER]";
                        std::cout << "\n";
                        std::cout << "  ; Preds: ";
                        if (blk.preds.empty())
                            std::cout << "(none)";
                        for (u32 p : blk.preds)
                            std::cout << "BB" << p << " ";
                        std::cout << "\n";
                        std::cout << "  ; Succs: ";
                        if (blk.succs.empty())
                            std::cout << "(none)";
                        for (u32 s : blk.succs)
                            std::cout << "BB" << s << " ";
                        std::cout << "\n";
                        std::cout << "  ;"
                            << std::string(60, '-')
                            << "\n";
                    }
                    break;
                }
            }

            // Print instruction
            std::cout << "  "
                      << std::hex << std::setw(8)
                      << std::setfill('0') << ins.offset
                      << "  "
                      << std::left << std::setw(10)
                      << ins.mnemonic
                      << ins.operands;

            // Annotation
            if (ins.cat == InstrCat::COND_JMP ||
                ins.cat == InstrCat::UNCOND_JMP)
                std::cout << "  ; → 0x" << std::hex
                          << ins.target;

            std::cout << std::dec << "\n";
        }
        sep('=');
    }

    // Print CFG summary
    static void print_cfg_summary(
            const CFG& cfg,
            const MalwareReport& rep) {
        hdr("CFG ANALYSIS SUMMARY");

        std::cout << "  Basic blocks    : "
                  << cfg.blocks.size() << "\n";
        std::cout << "  Instructions    : "
                  << cfg.instrs.size() << "\n";

        int reachable = 0, dead = 0, loops = 0;
        for (const auto& b : cfg.blocks) {
            if (b.reachable) reachable++;
            if (b.is_dead_code) dead++;
            if (b.is_loop_header) loops++;
        }
        std::cout << "  Reachable blocks: " << reachable << "\n";
        std::cout << "  Dead blocks     : " << dead << "\n";
        std::cout << "  Loop headers    : " << loops << "\n";
        std::cout << "  Back edges      : "
                  << cfg.back_edge_count() << "\n";
        std::cout << "  Cyclomatic comp : "
                  << rep.cyclomatic << "\n";

        sep();
        std::cout << "  BLOCK DETAILS:\n";
        sep();
        for (const auto& blk : cfg.blocks) {
            std::cout << "  " << std::left
                      << std::setw(20) << blk.label()
                      << " instrs="
                      << std::setw(4) << blk.instr_idx.size()
                      << " succs=";
            for (u32 s : blk.succs)
                std::cout << "BB" << s << " ";
            if (!blk.reachable) std::cout << "[DEAD]";
            if (blk.is_loop_header) std::cout << "[LOOP]";
            if (blk.dom_parent >= 0 &&
                static_cast<size_t>(blk.dom_parent)
                    != blk.id)
                std::cout << " idom=BB"
                          << blk.dom_parent;
            std::cout << "\n";
        }

        sep();
        std::cout << "  DOMINATOR TREE:\n";
        sep();
        print_dom_tree(cfg);

        sep('=');
    }

    // Print malware detection report
    static void print_malware_report(
            const MalwareReport& rep) {
        hdr("MALWARE / OBFUSCATION DETECTION REPORT");

        auto yn = [](bool v) { return v ? "YES" : "NO "; };

        std::cout << "  Infinite loops      : "
                  << yn(rep.has_infinite_loop) << "\n";
        std::cout << "  Dead code blocks    : "
                  << yn(rep.has_dead_code)
                  << " (" << rep.dead_block_count << " blocks)\n";
        std::cout << "  Indirect JMP        : "
                  << yn(rep.has_indirect_jmp) << "\n";
        std::cout << "  Self-ref loop       : "
                  << yn(rep.has_self_ref_loop) << "\n";
        std::cout << "  High cyclomatic     : "
                  << yn(rep.high_cyclomatic)
                  << " (M=" << rep.cyclomatic << ")\n";
        std::cout << "  High JMP ratio      : "
                  << yn(rep.many_unconditional) << "\n";
        std::cout << "  NOP/INT3 sled       : "
                  << yn(rep.has_int3_nop_sled) << "\n";
        std::cout << "  Suspicious shape    : "
                  << yn(rep.suspicious_cfg_shape) << "\n";

        sep();
        std::cout << "  Obfuscation score   : "
                  << rep.obfuscation_score << " / 100  ";
        int bar = rep.obfuscation_score / 5;
        std::cout << "[";
        for (int i = 0; i < 20; i++)
            std::cout << (i < bar ? "#" : ".");
        std::cout << "]\n\n";

        if (rep.findings.empty()) {
            std::cout << "  No suspicious patterns found.\n";
        } else {
            std::cout << "  FINDINGS:\n";
            for (const auto& f : rep.findings)
                std::cout << "    * " << f << "\n";
        }
        sep('=');
    }

private:
    static void print_dom_tree(const CFG& cfg) {
        // For each block, print its idom
        for (const auto& b : cfg.blocks) {
            if (!b.reachable) continue;
            int level = 0;
            int cur = static_cast<int>(b.id);
            // Walk up tree to find depth
            for (int steps = 0; steps < 20; steps++) {
                if (b.dom_parent < 0 || cur == 0) break;
                int parent = cfg.blocks[cur].dom_parent;
                if (parent == cur || parent < 0) break;
                cur = parent; level++;
            }
            std::cout << "  " << std::string(level*2,' ')
                      << b.label();
            if (b.is_loop_header) std::cout << " [LOOP]";
            std::cout << "\n";
        }
    }
};

// ============================================================
// ============================================================
//   SECTION 7 — SAMPLE BYTECODE LIBRARY
// ============================================================
// ============================================================
// These are hand-crafted x86-32 byte sequences that represent
// real code patterns seen in both legitimate software and
// malware samples. Safe to decode — no execution occurs.
// ============================================================

struct Sample {
    std::string         name;
    std::string         description;
    std::vector<u8>     bytes;
};

static std::vector<Sample> build_samples() {
    std::vector<Sample> samples;

    // --------------------------------------------------------
    // SAMPLE 1: Simple if-else structure
    // Corresponds to:
    //   int foo(int x) {
    //     if (x > 0) return 1;
    //     else return -1;
    //   }
    // --------------------------------------------------------
    samples.push_back({
        "Simple if-else",
        "Basic conditional branch with two paths merging",
        {
            0x55,             // PUSH ebp
            0x89, 0xE5,       // MOV ebp, esp
            0x8B, 0x45, 0x08, // MOV eax, [ebp+8]
            0x85, 0xC0,       // TEST eax, eax
            0x7E, 0x07,       // JLE +7  (else branch)
            0xB8, 0x01,0x00,0x00,0x00, // MOV eax, 1
            0xEB, 0x05,       // JMP +5  (skip else)
            0xB8, 0xFF,0xFF,0xFF,0xFF, // MOV eax, -1
            0x5D,             // POP ebp
            0xC3              // RET
        }
    });

    // --------------------------------------------------------
    // SAMPLE 2: For loop
    // Corresponds to:
    //   int sum(int n) {
    //     int s = 0;
    //     for (int i = 0; i < n; i++) s += i;
    //     return s;
    //   }
    // --------------------------------------------------------
    samples.push_back({
        "For loop (sum 0..n)",
        "Simple counting loop with back-edge",
        {
            0x55,             // PUSH ebp
            0x89, 0xE5,       // MOV ebp, esp
            0x31, 0xC0,       // XOR eax, eax  ; s = 0
            0x31, 0xC9,       // XOR ecx, ecx  ; i = 0
            0x3B, 0x4D, 0x08, // CMP ecx, [ebp+8]  ; i < n?
            0x7D, 0x06,       // JGE +6  (exit loop)
            0x01, 0xC8,       // ADD eax, ecx
            0x41,             // INC ecx
            0xEB, 0xF5,       // JMP -11 (loop back)
            0x5D,             // POP ebp
            0xC3              // RET
        }
    });

    // --------------------------------------------------------
    // SAMPLE 3: Switch statement (jump table simulation)
    // --------------------------------------------------------
    samples.push_back({
        "Switch with multiple cases",
        "Conditional chain mimicking switch/case",
        {
            0x55,             // PUSH ebp
            0x89, 0xE5,       // MOV ebp, esp
            0x8B, 0x45, 0x08, // MOV eax, [ebp+8]
            0x83, 0xF8, 0x01, // CMP eax, 1
            0x74, 0x0A,       // JZ case1
            0x83, 0xF8, 0x02, // CMP eax, 2
            0x74, 0x08,       // JZ case2
            0x83, 0xF8, 0x03, // CMP eax, 3
            0x74, 0x06,       // JZ case3
            0xB8, 0x00,0x00,0x00,0x00, // MOV eax, 0 default
            0xEB, 0x0F,       // JMP end
            0xB8, 0x0A,0x00,0x00,0x00, // case1: MOV eax, 10
            0xEB, 0x09,       // JMP end
            0xB8, 0x14,0x00,0x00,0x00, // case2: MOV eax, 20
            0xEB, 0x03,       // JMP end
            0xB8, 0x1E,0x00,0x00,0x00, // case3: MOV eax, 30
            0x5D,             // POP ebp
            0xC3              // RET
        }
    });

    // --------------------------------------------------------
    // SAMPLE 4: Recursive function (factorial)
    // --------------------------------------------------------
    samples.push_back({
        "Recursive factorial",
        "Self-calling function — CALL creates sub-CFG edge",
        {
            0x55,             // PUSH ebp
            0x89, 0xE5,       // MOV ebp, esp
            0x8B, 0x45, 0x08, // MOV eax, [ebp+8]
            0x83, 0xF8, 0x01, // CMP eax, 1
            0x7F, 0x05,       // JG recurse
            0xB8, 0x01,0x00,0x00,0x00, // MOV eax, 1
            0xEB, 0x0E,       // JMP done
            // recurse:
            0x48,             // DEC eax
            0x50,             // PUSH eax
            0xE8, 0xF0,0xFF,0xFF,0xFF, // CALL -16 (self)
            0x83, 0xC4, 0x04, // ADD esp, 4
            0x8B, 0x55, 0x08, // MOV edx, [ebp+8]
            0x0F, 0xAF, 0xC2, // IMUL eax, edx
            // done:
            0x5D,             // POP ebp
            0xC3              // RET
        }
    });

    // --------------------------------------------------------
    // SAMPLE 5: Obfuscated code with dead blocks + junk
    // Patterns seen in packed/obfuscated malware:
    //   - Dead code blocks (never reachable)
    //   - Opaque predicates (always-taken branches)
    //   - NOP sled
    //   - Indirect jump
    // --------------------------------------------------------
    samples.push_back({
        "Obfuscated malware-like code",
        "Dead code, opaque predicates, NOP sled, indirect JMP",
        {
            // NOP sled (8 bytes)
            0x90, 0x90, 0x90, 0x90,
            0x90, 0x90, 0x90, 0x90,
            // Opaque predicate: XOR eax,eax then JZ (always taken)
            0x31, 0xC0,       // XOR eax, eax  ; eax always 0
            0x74, 0x0A,       // JZ +10 (always taken — opaque pred)
            // DEAD BLOCK (never reached):
            0xB8,0xDE,0xAD,0xBE,0xEF, // MOV eax, 0xDEADBEEF
            0xFF, 0xE0,       // JMP eax (indirect — unreachable)
            0xCC, 0xCC, 0xCC, // INT3 x3
            // Real code (jump target):
            0x55,             // PUSH ebp
            0x89, 0xE5,       // MOV ebp, esp
            0x8B, 0x45, 0x08, // MOV eax, [ebp+8]
            0x40,             // INC eax
            0x5D,             // POP ebp
            0xC3              // RET
        }
    });

    // --------------------------------------------------------
    // SAMPLE 6: Infinite loop with self-modifying pattern
    // --------------------------------------------------------
    samples.push_back({
        "Infinite loop with counter",
        "Tight loop — ecx counter, back edge to itself",
        {
            0x31, 0xC9,       // XOR ecx, ecx
            // loop_top:
            0x41,             // INC ecx
            0x81, 0xF9,
              0x00,0x10,0x00,0x00, // CMP ecx, 0x1000
            0x7C, 0xF7,       // JL loop_top (-9)
            0x31, 0xC0,       // XOR eax, eax
            0xC3              // RET
        }
    });

    // --------------------------------------------------------
    // SAMPLE 7: String decoder loop (XOR decryption)
    // Classic malware payload decryption stub
    // --------------------------------------------------------
    samples.push_back({
        "XOR string decoder (malware decrypt stub)",
        "Byte-by-byte XOR loop over buffer — malware pattern",
        {
            0x55,             // PUSH ebp
            0x89, 0xE5,       // MOV ebp, esp
            0x8B, 0x75, 0x08, // MOV esi, [ebp+8]  ; buf ptr
            0x8B, 0x4D, 0x0C, // MOV ecx, [ebp+12] ; length
            0xB3, 0x42,       // MOV bl, 0x42      ; XOR key
            // decode_loop:
            0x8A, 0x06,       // MOV al, [esi]
            0x30, 0xD8,       // XOR al, bl
            0x88, 0x06,       // MOV [esi], al
            0x46,             // INC esi
            0xFE, 0xCB,       // DEC bl  (rolling key)
            0xE2, 0xF7,       // LOOP decode_loop (-9)
            0x5D,             // POP ebp
            0xC3              // RET
        }
    });

    return samples;
}

// ============================================================
// ============================================================
//   SECTION 8 — INTERACTIVE CLI
// ============================================================
// ============================================================

static void print_banner() {
    sep('=');
    std::cout << "\n"
"   ██████╗███████╗ ██████╗     ██████╗ ██╗   ██╗██╗██╗     ██████╗\n"
"  ██╔════╝██╔════╝██╔════╝     ██╔══██╗██║   ██║██║██║     ██╔══██╗\n"
"  ██║     █████╗  ██║  ███╗    ██████╔╝██║   ██║██║██║     ██║  ██║\n"
"  ██║     ██╔══╝  ██║   ██║    ██╔══██╗██║   ██║██║██║     ██║  ██║\n"
"  ╚██████╗██║     ╚██████╔╝    ██████╔╝╚██████╔╝██║███████╗██████╔╝\n"
"   ╚═════╝╚═╝      ╚═════╝     ╚═════╝  ╚═════╝ ╚═╝╚══════╝╚═════╝\n"
"\n"
"  Control Flow Graph Builder — x86-32 Bytecode Analyzer\n"
"  Disassembler + CFG + Dominators + Malware Detection + DOT Export\n"
"\n";
    sep('=');
}

static void print_menu(const std::vector<Sample>& samples) {
    std::cout << "\n";
    sep();
    std::cout << "  MAIN MENU\n";
    sep();
    std::cout << "  SAMPLE BYTECODES:\n";
    for (size_t i = 0; i < samples.size(); i++) {
        std::cout << "  " << (i + 1) << ". "
                  << samples[i].name << "\n"
                  << "     " << samples[i].description << "\n";
    }
    sep();
    std::cout << "  OTHER OPTIONS:\n";
    std::cout << "  8. Analyse custom hex bytes\n";
    std::cout << "  9. Run all samples (batch report)\n";
    std::cout << "  0. Exit\n";
    sep();
    std::cout << "  Choice: ";
}

static void run_analysis(const std::string& name,
                          const std::vector<u8>& bytes,
                          bool export_dot = true) {
    std::cout << "\n";
    hdr("ANALYZING: " + name);
    std::cout << "  Bytes: " << bytes.size() << "\n";
    std::cout << "  Hex  : ";
    for (size_t i = 0; i < std::min(bytes.size(),
                                      size_t(32)); i++)
        std::cout << std::hex << std::setw(2)
                  << std::setfill('0')
                  << static_cast<int>(bytes[i]) << " ";
    if (bytes.size() > 32) std::cout << "...";
    std::cout << std::dec << "\n\n";

    // Build CFG
    CFG cfg;
    cfg.build(bytes.data(), bytes.size(), 0x1000);
    cfg.detect_loops();

    // Run malware detection
    MalwareReport rep = MalwareDetector::analyse(cfg, bytes);

    // Print disassembly
    Printer::print_disassembly(cfg);

    // Print CFG summary
    Printer::print_cfg_summary(cfg, rep);

    // Print malware report
    Printer::print_malware_report(rep);

    // Export DOT file
    if (export_dot) {
        std::string dot_name = name;
        // Sanitize filename
        for (char& c : dot_name)
            if (c == ' ' || c == '/' || c == '\\') c = '_';
        dot_name = "cfg_" + dot_name + ".dot";
        DotExporter::write(cfg, rep, dot_name);
    }
}

int main() {
    print_banner();
    auto samples = build_samples();

    int choice = -1;
    while (choice != 0) {
        print_menu(samples);
        std::cin >> choice;
        std::cin.ignore();
        std::cout << "\n";

        if (choice >= 1 &&
            choice <= static_cast<int>(samples.size())) {
            const auto& s = samples[choice - 1];
            run_analysis(s.name, s.bytes, true);
        }
        else if (choice == 8) {
            std::cout << "  Enter hex bytes "
                         "(space-separated, e.g. 55 89 E5 C3): ";
            std::string line;
            std::getline(std::cin, line);
            std::vector<u8> bytes;
            std::istringstream iss(line);
            std::string token;
            while (iss >> token) {
                try {
                    bytes.push_back(static_cast<u8>(
                        std::stoul(token, nullptr, 16)));
                } catch (...) {}
            }
            if (bytes.empty()) {
                std::cout << "  No valid bytes entered.\n";
            } else {
                run_analysis("custom_input", bytes, true);
            }
        }
        else if (choice == 9) {
            hdr("BATCH ANALYSIS — ALL SAMPLES");
            for (const auto& s : samples) {
                CFG cfg;
                cfg.build(s.bytes.data(), s.bytes.size(),
                           0x1000);
                cfg.detect_loops();
                MalwareReport rep = MalwareDetector::analyse(
                    cfg, s.bytes);

                std::cout << "\n  "
                          << std::left << std::setw(38)
                          << s.name
                          << " blocks=" << std::setw(3)
                          << cfg.blocks.size()
                          << " M=" << std::setw(3)
                          << rep.cyclomatic
                          << " dead=" << std::setw(2)
                          << rep.dead_block_count
                          << " score=" << std::setw(3)
                          << rep.obfuscation_score
                          << "/100\n";

                if (!rep.findings.empty()) {
                    for (const auto& f : rep.findings)
                        std::cout << "    ⚠ " << f << "\n";
                }
            }
            sep('=');
        }
        else if (choice == 0) {
            sep('=');
            std::cout << "  Exiting CFG Builder.\n";
            sep('=');
        }
        else {
            std::cout << "  Invalid option.\n";
        }
    }

    return 0;
}