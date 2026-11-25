#include "linux_seccomp_bpf.h"

enum {
    BPF_LD = 0x00, BPF_LDX = 0x01, BPF_ST = 0x02, BPF_STX = 0x03,
    BPF_ALU = 0x04, BPF_JMP = 0x05, BPF_RET = 0x06, BPF_MISC = 0x07,
    BPF_K = 0x00, BPF_X = 0x08, BPF_A = 0x10,
    BPF_W = 0x00, BPF_IMM = 0x00, BPF_ABS = 0x20, BPF_MEM = 0x60, BPF_LEN = 0x80,
    BPF_ADD = 0x00, BPF_SUB = 0x10, BPF_MUL = 0x20, BPF_DIV = 0x30, BPF_OR = 0x40,
    BPF_AND = 0x50, BPF_LSH = 0x60, BPF_RSH = 0x70, BPF_NEG = 0x80, BPF_XOR = 0xa0,
    BPF_JA = 0x00, BPF_JEQ = 0x10, BPF_JGT = 0x20, BPF_JGE = 0x30, BPF_JSET = 0x40,
    BPF_TAX = 0x00, BPF_TXA = 0x80,
    BPF_MEM_WORDS = 16, BPF_MEM_VALID = 0xffff,
};

#define ALU_CASES(op) case BPF_ALU | (op) | BPF_K: case BPF_ALU | (op) | BPF_X
#define JMP_CASES(op) case BPF_JMP | (op) | BPF_K: case BPF_JMP | (op) | BPF_X
#define SECCOMP_KILL_PROCESS 0x80000000u

static bool context_offset(u32 offset) {
    return offset < sizeof(struct linux64_seccomp_data) && !(offset & 3u);
}

bool linux64_seccomp_bpf_validate(const struct linux64_bpf_insn *program, u32 count) {
    if (!program || !count || count > LINUX64_BPF_MAX_INSNS) return false;
    if (program[count - 1].code != (BPF_RET | BPF_K) &&
        program[count - 1].code != (BPF_RET | BPF_A)) return false;

    u16 incoming[LINUX64_BPF_MAX_INSNS];
    for (u32 pc = 0; pc < count; ++pc) incoming[pc] = BPF_MEM_VALID;

    /* Для загрузки слова scratch нужны записи на всех входящих путях. */
    u16 stored = 0;
    for (u32 pc = 0; pc < count; ++pc) {
        const struct linux64_bpf_insn *insn = &program[pc];
        u32 remaining = count - pc - 1;
        stored &= incoming[pc];
        switch (insn->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            if (!context_offset(insn->k)) return false;
            break;
        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
            if (insn->k >= BPF_MEM_WORDS || !(stored & (1u << insn->k))) return false;
            break;
        case BPF_ST:
        case BPF_STX:
            if (insn->k >= BPF_MEM_WORDS) return false;
            stored |= 1u << insn->k;
            break;
        case BPF_ALU | BPF_DIV | BPF_K:
            if (!insn->k) return false;
            break;
        case BPF_ALU | BPF_LSH | BPF_K:
        case BPF_ALU | BPF_RSH | BPF_K:
            if (insn->k >= 32) return false;
            break;
        case BPF_JMP | BPF_JA:
            if (insn->k >= remaining) return false;
            incoming[pc + 1 + insn->k] &= stored;
            stored = BPF_MEM_VALID;
            break;
        JMP_CASES(BPF_JEQ):
        JMP_CASES(BPF_JGT):
        JMP_CASES(BPF_JGE):
        JMP_CASES(BPF_JSET):
            if (insn->jt >= remaining || insn->jf >= remaining) return false;
            incoming[pc + 1 + insn->jt] &= stored;
            incoming[pc + 1 + insn->jf] &= stored;
            stored = BPF_MEM_VALID;
            break;
        case BPF_LD | BPF_W | BPF_LEN:
        case BPF_LDX | BPF_W | BPF_LEN:
        case BPF_LD | BPF_IMM:
        case BPF_LDX | BPF_IMM:
        case BPF_MISC | BPF_TAX:
        case BPF_MISC | BPF_TXA:
        case BPF_RET | BPF_K:
        case BPF_RET | BPF_A:
        case BPF_ALU | BPF_DIV | BPF_X:
        case BPF_ALU | BPF_LSH | BPF_X:
        case BPF_ALU | BPF_RSH | BPF_X:
        case BPF_ALU | BPF_NEG:
        ALU_CASES(BPF_ADD):
        ALU_CASES(BPF_SUB):
        ALU_CASES(BPF_MUL):
        ALU_CASES(BPF_OR):
        ALU_CASES(BPF_AND):
        ALU_CASES(BPF_XOR):
            break;
        default:
            return false;
        }
    }
    return true;
}

u32 linux64_seccomp_bpf_run(const struct linux64_bpf_insn *program, u32 count,
                           const struct linux64_seccomp_data *data) {
    if (!program || !count || count > LINUX64_BPF_MAX_INSNS || !data) return SECCOMP_KILL_PROCESS;
    u32 accumulator = 0, index = 0, memory[BPF_MEM_WORDS];
    u16 stored = 0;
    for (u32 pc = 0; pc < count;) {
        const struct linux64_bpf_insn *insn = &program[pc++];
        u32 operand = insn->code & BPF_X ? index : insn->k;
        u32 offset;
        switch (insn->code) {
        case BPF_LD | BPF_W | BPF_ABS:
            if (!context_offset(insn->k)) return SECCOMP_KILL_PROCESS;
            __builtin_memcpy(&accumulator, (const u8 *)data + insn->k, sizeof(accumulator));
            break;
        case BPF_LD | BPF_W | BPF_LEN: accumulator = sizeof(*data); break;
        case BPF_LDX | BPF_W | BPF_LEN: index = sizeof(*data); break;
        case BPF_LD | BPF_IMM: accumulator = insn->k; break;
        case BPF_LDX | BPF_IMM: index = insn->k; break;
        case BPF_LD | BPF_MEM:
        case BPF_LDX | BPF_MEM:
            if (insn->k >= BPF_MEM_WORDS || !(stored & (1u << insn->k))) return SECCOMP_KILL_PROCESS;
            if (insn->code == (BPF_LD | BPF_MEM)) accumulator = memory[insn->k];
            else index = memory[insn->k];
            break;
        case BPF_ST:
        case BPF_STX:
            if (insn->k >= BPF_MEM_WORDS) return SECCOMP_KILL_PROCESS;
            memory[insn->k] = insn->code == BPF_ST ? accumulator : index;
            stored |= 1u << insn->k;
            break;
        case BPF_MISC | BPF_TAX: index = accumulator; break;
        case BPF_MISC | BPF_TXA: accumulator = index; break;
        case BPF_ALU | BPF_NEG: accumulator = 0u - accumulator; break;
        ALU_CASES(BPF_ADD): accumulator += operand; break;
        ALU_CASES(BPF_SUB): accumulator -= operand; break;
        ALU_CASES(BPF_MUL): accumulator *= operand; break;
        ALU_CASES(BPF_DIV):
            /* Деление на нуль через X завершает классический BPF с результатом 0. */
            if (!operand) return 0;
            accumulator /= operand;
            break;
        ALU_CASES(BPF_OR): accumulator |= operand; break;
        ALU_CASES(BPF_AND): accumulator &= operand; break;
        ALU_CASES(BPF_XOR): accumulator ^= operand; break;
        ALU_CASES(BPF_LSH): accumulator <<= operand & 31u; break;
        ALU_CASES(BPF_RSH): accumulator >>= operand & 31u; break;
        case BPF_JMP | BPF_JA: offset = insn->k; goto jump;
        JMP_CASES(BPF_JEQ): offset = accumulator == operand ? insn->jt : insn->jf; goto jump;
        JMP_CASES(BPF_JGT): offset = accumulator > operand ? insn->jt : insn->jf; goto jump;
        JMP_CASES(BPF_JGE): offset = accumulator >= operand ? insn->jt : insn->jf; goto jump;
        JMP_CASES(BPF_JSET): offset = accumulator & operand ? insn->jt : insn->jf; goto jump;
        case BPF_RET | BPF_K: return insn->k;
        case BPF_RET | BPF_A: return accumulator;
        default: return SECCOMP_KILL_PROCESS;
        }
        continue;
    jump:
        if (offset >= count - pc) return SECCOMP_KILL_PROCESS;
        pc += offset;
    }
    return SECCOMP_KILL_PROCESS;
}
