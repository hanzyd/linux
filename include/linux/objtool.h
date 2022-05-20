/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_OBJTOOL_H
#define _LINUX_OBJTOOL_H

/*
 * UNWIND_HINT_TYPE_CALL: Indicates that sp_reg+sp_offset resolves to PREV_SP
 * (the caller's SP right before it made the call).  Used for all callable
 * functions, i.e. all C code and all callable asm functions.
 *
 * UNWIND_HINT_TYPE_REGS: Used in entry code to indicate that sp_reg+sp_offset
 * points to a fully populated pt_regs from a syscall, interrupt, or exception.
 *
 * UNWIND_HINT_TYPE_REGS_PARTIAL: Used in entry code to indicate that
 * sp_reg+sp_offset points to the iret return frame.
 *
 * UNWIND_HINT_FUNC: Generate the unwind metadata of a callable function.
 * Useful for code which doesn't have an ELF function annotation.
 */
#define UNWIND_HINT_TYPE_CALL		0
#define UNWIND_HINT_TYPE_REGS		1
#define UNWIND_HINT_TYPE_REGS_PARTIAL	2
#define UNWIND_HINT_TYPE_FUNC		3

#ifdef CONFIG_STACK_VALIDATION

#ifndef __ASSEMBLY__

/*
 * This macro marks the given function's stack frame as "non-standard", which
 * tells objtool to ignore the function when doing stack metadata validation.
 * It should only be used in special cases where you're 100% sure it won't
 * affect the reliability of frame pointers and kernel stack traces.
 *
 * For more information, see tools/objtool/Documentation/stack-validation.txt.
 */
#define STACK_FRAME_NON_STANDARD(func) \
	static void __used __section(".discard.func_stack_frame_non_standard") \
		*__func_stack_frame_non_standard_##func = func

/*
 * STACK_FRAME_NON_STANDARD_FP() is a frame-pointer-specific function ignore
 * for the case where a function is intentionally missing frame pointer setup,
 * but otherwise needs objtool/ORC coverage when frame pointers are disabled.
 */
#ifdef CONFIG_FRAME_POINTER
#define STACK_FRAME_NON_STANDARD_FP(func) STACK_FRAME_NON_STANDARD(func)
#else
#define STACK_FRAME_NON_STANDARD_FP(func)
#endif

#define ANNOTATE_NOENDBR					\
	"986: \n\t"						\
	".pushsection .discard.noendbr\n\t"			\
	_ASM_PTR " 986b\n\t"					\
	".popsection\n\t"

#define ASM_REACHABLE							\
	"998:\n\t"							\
	".pushsection .discard.reachable\n\t"				\
	".long 998b - .\n\t"						\
	".popsection\n\t"

#else /* __ASSEMBLY__ */

/*
 * This macro indicates that the following intra-function call is valid.
 * Any non-annotated intra-function call will cause objtool to issue a warning.
 */
#define ANNOTATE_INTRA_FUNCTION_CALL				\
	999:							\
	.pushsection .discard.intra_function_calls;		\
	.long 999b;						\
	.popsection;

.macro STACK_FRAME_NON_STANDARD func:req
	.pushsection .discard.func_stack_frame_non_standard, "aw"
		.long \func - .
	.popsection
.endm

.macro ANNOTATE_NOENDBR
.Lhere_\@:
	.pushsection .discard.noendbr
	.quad	.Lhere_\@
	.popsection
.endm

.macro REACHABLE
.Lhere_\@:
	.pushsection .discard.reachable
	.long	.Lhere_\@ - .
	.popsection
.endm

#endif /* __ASSEMBLY__ */

#else /* !CONFIG_STACK_VALIDATION */

#ifndef __ASSEMBLY__

#define STACK_FRAME_NON_STANDARD(func)
#define STACK_FRAME_NON_STANDARD_FP(func)
#define ANNOTATE_NOENDBR
#define ASM_REACHABLE
#else
#define ANNOTATE_INTRA_FUNCTION_CALL
.macro STACK_FRAME_NON_STANDARD func:req
.endm
.macro ANNOTATE_NOENDBR
.endm
.macro REACHABLE
.endm
#endif

#endif /* CONFIG_STACK_VALIDATION */

#endif /* _LINUX_OBJTOOL_H */
