// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * decode.c - ARM64 instruction decoder for dynamic FP validation. Only a
 *            small subset of the instructions need to be decoded.
 *
 * Author: Madhavan T. Venkataraman (madvenka@linux.microsoft.com)
 *
 * Copyright (C) 2022 Microsoft Corporation
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <objtool/insn.h>
#include <objtool/elf.h>
#include <objtool/warn.h>
#include <arch/cfi_regs.h>

/* ARM64 instructions are all 4 bytes wide. */
#define INSN_SIZE	4

/* --------------------- instruction decode struct ------------------------- */

struct decode {
	unsigned long	opmask;
	unsigned long	op;
	unsigned int	shift;
	unsigned int	bits;
	unsigned int	size;
	unsigned int	sign_extend;
	void		(*func)(struct decode *decode,
				u32 insn, enum insn_type *type,
				s64 *imm, struct list_head *stack_ops);
};

/* --------------------- arch support functions ------------------------- */

unsigned long arch_dest_reloc_offset(int addend)
{
	return addend;
}

unsigned long arch_jump_destination(struct instruction *insn)
{
	return insn->offset + insn->immediate;
}

/* --------------------- miscellaneous functions --------------------------- */

static void reg_check(unsigned int sp_check, unsigned int fp_check,
		      u32 insn, enum insn_type *type)
{
	unsigned int	rd = insn & 0x1F;

	if ((sp_check && rd == CFI_SP) || (fp_check && rd == CFI_FP))
		*type = INSN_UNRELIABLE;
}

static void add_stack_op(unsigned char src, unsigned char dest, s64 offset,
			 struct list_head *stack_ops)
{
	struct stack_op *op;

	op = calloc(1, sizeof(*op));
	if (!op) {
		WARN("calloc failed");
		return;
	}

	op->src.reg = src;
	op->src.type = OP_SRC_ADD;
	op->src.offset = offset;
	op->dest.reg = dest;
	op->dest.type = OP_DEST_REG;

	list_add_tail(&op->list, stack_ops);
}

/* ------------------------ decode functions ------------------------------- */

#define STP_SOFF	0x29000000	/* STP signed offset */
#define STR_SOFF	0xB9000000	/* STR signed offset */
#define LDP_SOFF	0x29400000	/* LDP signed offset */
#define LDR_SOFF	0xB9400000	/* LDR signed offset */

/* Load-Store instructions. */
static void ld_st(struct decode *decode,
		       u32 insn, enum insn_type *type,
		       s64 *imm, struct list_head *stack_ops)
{
	unsigned int	rn = (insn >> 5) & 0x1F;

	if (decode->op == LDP_SOFF || decode->op == LDR_SOFF ||
	    decode->op == STP_SOFF || decode->op == STR_SOFF)
		return;
	if (rn == CFI_SP)
		add_stack_op(CFI_SP, CFI_SP, *imm, stack_ops);
	else if (rn == CFI_FP)
		add_stack_op(CFI_FP, CFI_FP, *imm, stack_ops);
}

/* Load-Store instructions. */
static void ld_st_chk(struct decode *decode,
			     u32 insn, enum insn_type *type,
			     s64 *imm, struct list_head *stack_ops)
{
	ld_st(decode, insn, type, imm, stack_ops);
	reg_check(0, 1, insn, type);
}

#define CMN_OP		0x31000000	/* Alias of ADDS imm */
#define CMP_OP		0x71000000	/* Alias of SUBS imm */

/* Add instructions. */
static void add(struct decode *decode,
		u32 insn, enum insn_type *type,
		s64 *imm, struct list_head *stack_ops)
{
	unsigned int	rd = insn & 0x1F;
	unsigned int	rn = (insn >> 5) & 0x1F;
	unsigned int	shift = (insn >> 22) & 1;

	if (shift)
		*imm <<= 12;

	if (rd == CFI_SP) {
		if (rn == CFI_SP)
			add_stack_op(CFI_SP, CFI_SP, *imm, stack_ops);
		else if (rn == CFI_FP)
			add_stack_op(CFI_FP, CFI_SP, *imm, stack_ops);
		else if (decode->op != CMN_OP && decode->op != CMP_OP)
			*type = INSN_UNRELIABLE;
	} else if (rd == CFI_FP) {
		if (rn == CFI_SP)
			add_stack_op(CFI_SP, CFI_FP, *imm, stack_ops);
		else if (rn == CFI_FP)
			add_stack_op(CFI_FP, CFI_FP, *imm, stack_ops);
		else
			*type = INSN_UNRELIABLE;
	}
}

/* Subtract instructions. */
static void sub(struct decode *decode,
		u32 insn, enum insn_type *type,
		s64 *imm, struct list_head *stack_ops)
{
	*imm = -(*imm);
	return add(decode, insn, type, imm, stack_ops);
}

#define BR_UNCONDITIONAL		0x14000000

/* Branch and Return instructions. */
static void branch(struct decode *decode,
		   u32 insn, enum insn_type *type,
		   s64 *imm, struct list_head *stack_ops)
{
	if (*imm) {
		if (decode->op == BR_UNCONDITIONAL)
			*type = INSN_JUMP_UNCONDITIONAL;
		else
			*type = INSN_JUMP_CONDITIONAL;
	} else {
		*type = INSN_JUMP_DYNAMIC;
	}
}

static void call(struct decode *decode,
		   u32 insn, enum insn_type *type,
		   s64 *imm, struct list_head *stack_ops)
{
	*type = *imm ? INSN_CALL : INSN_CALL_DYNAMIC;
}

static void ret(struct decode *decode,
		u32 insn, enum insn_type *type,
		s64 *imm, struct list_head *stack_ops)
{
	*type = INSN_RETURN;
}

static void bug(struct decode *decode,
		u32 insn, enum insn_type *type,
		s64 *imm, struct list_head *stack_ops)
{
	*type = INSN_BUG;
}

/*
 * Other instructions are not decoded. They don't generate any stack_ops.
 * Only checks are done to make sure that the compiler does not generate
 * any instructions to clobber the SP and FP registers in unexpected ways.
 */
static void sp_check(struct decode *decode,
		     u32 insn, enum insn_type *type,
		     s64 *imm, struct list_head *stack_ops)
{
	reg_check(1, 1, insn, type);
}

static void fp_check(struct decode *decode,
		  u32 insn, enum insn_type *type,
		  s64 *imm, struct list_head *stack_ops)
{
	reg_check(0, 1, insn, type);
}

static void ignore(struct decode *decode,
		   u32 insn, enum insn_type *type,
		   s64 *imm, struct list_head *stack_ops)
{
}

/* ------------------------ Instruction decode ----------------------------- */

struct decode	decode_array[] = {
/* =============================== INSTRUCTIONS =============================*/
/* operation           mask        opcode      shift bits size sign func     */
/* ==========================================================================*/
/* LDP pre */        { 0x7FC00000, 0x29C00000, 15,   7,   8,   1,   ld_st },
/* LDP post */       { 0x7FC00000, 0x28C00000, 15,   7,   8,   1,   ld_st },
/* LDP off */        { 0x7FC00000, 0x29400000, 15,   7,   8,   1,   ld_st },
/* LDPSW pre */      { 0xFFC00000, 0x69C00000, 15,   7,   4,   1,   ld_st_chk },
/* LDPSW post */     { 0xFFC00000, 0x68C00000, 15,   7,   4,   1,   ld_st_chk },
/* LDR imm pre */    { 0xBFE00C00, 0xB8400C00, 12,   9,   1,   1,   ld_st },
/* LDR imm post */   { 0xBFE00C00, 0xB8400400, 12,   9,   1,   1,   ld_st },
/* LDR off */        { 0xBFC00000, 0xB9400000, 12,   9,   1,   1,   ld_st },
/* LDRB imm pre */   { 0xFFE00C00, 0x38400C00, 12,   9,   1,   1,   ld_st_chk },
/* LDRB imm post */  { 0xFFE00C00, 0x38400400, 12,   9,   1,   1,   ld_st_chk },
/* LDRH imm pre */   { 0xFFE00C00, 0x78400C00, 12,   9,   1,   1,   ld_st_chk },
/* LDRH imm post */  { 0xFFE00C00, 0x78400400, 12,   9,   1,   1,   ld_st_chk },
/* LDRSB imm pre */  { 0xFF800C00, 0x38800C00, 12,   9,   1,   1,   ld_st_chk },
/* LDRSB imm post */ { 0xFF800C00, 0x38800400, 12,   9,   1,   1,   ld_st_chk },
/* LDRSH imm pre */  { 0xFF800C00, 0x78800C00, 12,   9,   1,   1,   ld_st_chk },
/* LDRSH imm post */ { 0xFF800C00, 0x78800400, 12,   9,   1,   1,   ld_st_chk },
/* LDRSW imm pre */  { 0xFFE00C00, 0xB8800C00, 12,   9,   1,   1,   ld_st_chk },
/* LDRSW imm post */ { 0xFFE00C00, 0xB8800400, 12,   9,   1,   1,   ld_st_chk },
/* STP pre */        { 0x7FC00000, 0x29800000, 15,   7,   8,   1,   ld_st },
/* STP post */       { 0x7FC00000, 0x28800000, 15,   7,   8,   1,   ld_st },
/* STP off */        { 0x7FC00000, 0x29000000, 15,   7,   8,   1,   ld_st },
/* STGP imm pre */   { 0xFFC00000, 0x69800000, 15,   7,  16,   1,   ld_st },
/* STGP imm post */  { 0xFFC00000, 0x68800000, 15,   7,  16,   1,   ld_st },
/* STR imm pre */    { 0xBFC00C00, 0xB8000C00, 12,   9,   1,   1,   ld_st },
/* STR imm post */   { 0xBFC00C00, 0xB8000400, 12,   9,   1,   1,   ld_st },
/* STR off */        { 0xBFC00000, 0xB9000000, 10,  12,   1,   1,   ld_st },
/* STG imm pre */    { 0xFFC00C00, 0xD9000C00, 12,   9,  16,   1,   ld_st },
/* STG imm post */   { 0xFFC00C00, 0xD9000400, 12,   9,  16,   1,   ld_st },
/* ST2G imm pre */   { 0xFFE00C00, 0xD9A00C00, 12,   9,  16,   1,   ld_st },
/* ST2G imm post */  { 0xFFE00C00, 0xD9A00400, 12,   9,  16,   1,   ld_st },
/* ADD imm */        { 0x7F800000, 0x11000000, 10,  12,   1,   0,   add },
/* ADDS imm */       { 0x7F800000, 0x31000000, 10,  12,   1,   0,   add },
/* ADD ext reg */    { 0x7FE00000, 0x0B200000,  0,   0,   1,   0,   sp_check },
/* SUB imm */        { 0x7F800000, 0x51000000, 10,  12,   1,   0,   sub },
/* SUBS imm */       { 0x7F800000, 0x71000000, 10,  12,   1,   0,   sub },
/* SUB ext reg */    { 0x7FE00000, 0x4B200000,  0,   0,   1,   0,   sp_check },
/* ORR imm */        { 0x7F800000, 0x32000000,  0,   0,   1,   0,   sp_check },
/* B */              { 0xFC000000, 0x14000000,  0,  26,   4,   1,   branch },
/* B.cond */         { 0xFF000010, 0x54000000,  5,  19,   4,   1,   branch },
/* BC.cond */        { 0xFF000010, 0x54000010,  5,  19,   4,   1,   branch },
/* BR */             { 0xFFFFFC00, 0xD61F0000,  0,   0,   4,   0,   branch },
/* BRA */            { 0xFEFFF800, 0xD61F0800,  0,   0,   4,   0,   branch },
/* CBZ */            { 0x7F000000, 0x34000000,  5,  19,   4,   1,   branch },
/* CBNZ */           { 0x7F000000, 0x35000000,  5,  19,   4,   1,   branch },
/* TBZ */            { 0x7F000000, 0x36000000,  5,  14,   4,   1,   branch },
/* TBNZ */           { 0x7F000000, 0x37000000,  5,  14,   4,   1,   branch },
/* BL */             { 0xFC000000, 0x94000000,  0,  26,   4,   1,   call },
/* BLR */            { 0xFFFFFC00, 0xD63F0000,  0,   0,   4,   1,   call },
/* BLRA */           { 0xFEFFF800, 0xD63F0800,  0,   0,   4,   1,   call },
/* RET */            { 0xFFFFFC1F, 0xD65F0000,  0,   0,   1,   0,   ret },
/* RETA */           { 0xFFFFFBFF, 0xD65F0BFF,  0,   0,   1,   0,   ret },
/* ERET */           { 0xFFFFFFFF, 0xD69F03E0,  0,   0,   1,   0,   ret },
/* ERETA */          { 0xFFFFFBFF, 0xD69F0BFF,  0,   0,   1,   0,   ret },
/* BRK */            { 0xFFE00000, 0xD4200000,  0,   0,   1,   0,   bug },

/* =========================== INSTRUCTION CLASSES ==========================*/
/* operation           mask        opcode      shift bits size sign func     */
/* ==========================================================================*/
/* RSVD_00 */        { 0x1E000000, 0x00000000,  0,   0,   1,   0,   ignore },
/* UNALLOC_01 */     { 0x1E000000, 0x02000000,  0,   0,   1,   0,   ignore },
/* SVE_02 */         { 0x1E000000, 0x04000000,  0,   0,   1,   0,   ignore },
/* UNALLOC_03 */     { 0x1E000000, 0x06000000,  0,   0,   1,   0,   ignore },
/* LOAD_STORE_04 */  { 0x1E000000, 0x08000000,  0,   0,   1,   0,   fp_check },
/* DP_REGISTER_05 */ { 0x1E000000, 0x0A000000,  0,   0,   1,   0,   fp_check },
/* LOAD_STORE_06 */  { 0x1E000000, 0x0C000000,  0,   0,   1,   0,   ignore },
/* SIMD_FP_07 */     { 0x1E000000, 0x0E000000,  0,   0,   1,   0,   ignore },
/* DP_IMMEDIATE_08 */{ 0x1E000000, 0x10000000,  0,   0,   1,   0,   fp_check },
/* DP_IMMEDIATE_09 */{ 0x1E000000, 0x12000000,  0,   0,   1,   0,   fp_check },
/* BR_SYS_10 */      { 0x1E000000, 0x14000000,  0,   0,   1,   0,   fp_check },
/* BR_SYS_11 */      { 0x1E000000, 0x16000000,  0,   0,   1,   0,   fp_check },
/* LOAD_STORE_12 */  { 0x1E000000, 0x18000000,  0,   0,   1,   0,   fp_check },
/* DP_REGISTER_13 */ { 0x1E000000, 0x1A000000,  0,   0,   1,   0,   ignore },
/* LOAD_STORE_14 */  { 0x1E000000, 0x1C000000,  0,   0,   1,   0,   fp_check },
/* SIMD_FP_15 */     { 0x1E000000, 0x1E000000,  0,   0,   1,   0,   ignore },
};
unsigned int	ndecode = ARRAY_SIZE(decode_array);

static inline s64 sign_extend(s64 imm, unsigned int bits)
{
	return (imm << (64 - bits)) >> (64 - bits);
}

/*
 * This decoder is only for generating stack ops for instructions that
 * affect the SP and FP. The instructions that involve only immediate
 * operands can be evaluated in this decoder. But instructions that
 * involve other registers cannot be evaluated because the contents of
 * those registers are known only at runtime. There are checks to catch
 * it if the compiler generates these for the FP and SP. Such instructions
 * are marked as unreliable.
 */
int arch_decode_instruction(struct objtool_file *file,
			    const struct section *sec,
			    unsigned long offset, unsigned int maxlen,
			    unsigned int *len, enum insn_type *type,
			    unsigned long *immediate,
			    struct list_head *stack_ops)
{
	struct decode		*decode;
	s64			imm;
	u32			insn;
	unsigned int		mask, i;

	if (maxlen < INSN_SIZE)
		return -1;

	insn = *(u32 *)(sec->data->d_buf + offset);
	*type = INSN_OTHER;
	*len = INSN_SIZE;

	/*
	 * Find the decode structure for the specific instruction,
	 * if listed.
	 */
	for (i = 0; i < ndecode; i++) {
		decode = &decode_array[i];
		if ((insn & decode->opmask) == decode->op) {
			/*
			 * Decode the instruction.
			 */
			mask = (1 << decode->bits) - 1;
			imm = (insn >> decode->shift) & mask;
			if (decode->sign_extend)
				imm = sign_extend(imm, decode->bits);
			imm *= decode->size;

			decode->func(decode, insn, type, &imm, stack_ops);
			*immediate = imm;
			return 0;
		}
	}
	/* Cannot happen. */
	return -1;
}
