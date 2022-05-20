/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_ARM64_UNWIND_HINTS_H
#define _ASM_ARM64_UNWIND_HINTS_H

#ifndef __ASSEMBLY__

#include <linux/types.h>

/*
 * This struct is used by asm and inline asm code to manually annotate the
 * CFI for an instruction. We have to use s16 instead of s8 for some of these
 * fields as 8-bit fields are not relocated by some assemblers.
 */
struct unwind_hint {
	u32		ip;
	s16		sp_offset;
	s16		sp_reg;
	s16		type;
	s16		end;
};

#endif

#include <linux/objtool.h>

#include "orc_types.h"

#ifdef CONFIG_STACK_VALIDATION

#ifndef __ASSEMBLY__

#define UNWIND_HINT(sp_reg, sp_offset, type, end)		\
	"987: \n\t"						\
	".pushsection .discard.unwind_hints\n\t"		\
	/* struct unwind_hint */				\
	".long 987b - .\n\t"					\
	".short " __stringify(sp_offset) "\n\t"			\
	".short " __stringify(sp_reg) "\n\t"			\
	".short " __stringify(type) "\n\t"			\
	".short " __stringify(end) "\n\t"			\
	".popsection\n\t"

#else /* __ASSEMBLY__ */

/*
 * There are points in ASM code where it is useful to unwind through even
 * though the ASM code itself may be unreliable from an unwind perspective.
 * E.g., interrupt and exception handlers.
 *
 * These macros provide hints to objtool to compute the CFI information at
 * such instructions.
 */
.macro UNWIND_HINT sp_reg:req sp_offset=0 type:req end=0
.Lunwind_hint_pc_\@:
	.pushsection .discard.unwind_hints
		/* struct unwind_hint */
		.long .Lunwind_hint_pc_\@ - .
		.short \sp_offset
		.short \sp_reg
		.short \type
		.short \end
	.popsection
.endm

#endif /* __ASSEMBLY__ */

#else /* !CONFIG_STACK_VALIDATION */

#ifndef __ASSEMBLY__

#define UNWIND_HINT(sp_reg, sp_offset, type, end)	\
	"\n\t"
#else
.macro UNWIND_HINT sp_reg:req sp_offset=0 type:req end=0
.endm
#endif

#endif /* CONFIG_STACK_VALIDATION */
#ifdef __ASSEMBLY__

.macro UNWIND_HINT_FTRACE, offset
	.set sp_reg, ORC_REG_SP
	.set sp_offset, \offset
	.set type, UNWIND_HINT_TYPE_FTRACE
	UNWIND_HINT sp_reg=sp_reg sp_offset=sp_offset type=type
.endm

.macro UNWIND_HINT_REGS, offset
	.set sp_reg, ORC_REG_SP
	.set sp_offset, \offset
	.set type, UNWIND_HINT_TYPE_REGS
	UNWIND_HINT sp_reg=sp_reg sp_offset=sp_offset type=type
.endm

.macro UNWIND_HINT_IRQ, offset
	.set sp_reg, ORC_REG_SP
	.set sp_offset, \offset
	.set type, UNWIND_HINT_TYPE_IRQ_STACK
	UNWIND_HINT sp_reg=sp_reg sp_offset=sp_offset type=type
.endm

#endif /* __ASSEMBLY__ */

#endif /* _ASM_ARM64_UNWIND_HINTS_H */
