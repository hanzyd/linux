// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Madhavan T. Venkataraman (madvenka@linux.microsoft.com)
 *
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

#include <objtool/builtin.h>
#include <objtool/insn.h>
#include <objtool/warn.h>

static bool	fill;

/*
 * Find the destination instructions for all jumps.
 */
static void add_jump_destinations(struct objtool_file *file)
{
	struct instruction *insn;
	struct reloc *reloc;
	struct section *dest_sec;
	unsigned long dest_off;

	for_each_insn(file, insn) {
		if (insn->type != INSN_CALL &&
		    insn->type != INSN_JUMP_CONDITIONAL &&
		    insn->type != INSN_JUMP_UNCONDITIONAL) {
			continue;
		}

		reloc = insn_reloc(file, insn);
		if (!reloc) {
			dest_sec = insn->sec;
			dest_off = arch_jump_destination(insn);
		} else if (reloc->sym->type == STT_SECTION) {
			dest_sec = reloc->sym->sec;
			dest_off = arch_dest_reloc_offset(reloc->addend);
		} else if (reloc->sym->sec->idx) {
			dest_sec = reloc->sym->sec;
			dest_off = reloc->sym->sym.st_value +
				   arch_dest_reloc_offset(reloc->addend);
		} else {
			/* non-func asm code jumping to another file */
			continue;
		}

		insn->jump_dest = find_insn(file, dest_sec, dest_off);
	}
}

static void update_cfi_state(struct cfi_state *cfi, struct stack_op *op)
{
	struct cfi_reg *cfa = &cfi->cfa;
	struct cfi_reg *regs = cfi->regs;

	if (op->src.reg == CFI_SP) {
		if (op->dest.reg == CFI_SP)
			cfa->offset -= op->src.offset;
		else
			regs[CFI_FP].offset = -cfa->offset + op->src.offset;
	} else {
		if (op->dest.reg == CFI_SP)
			cfa->offset = -(regs[CFI_FP].offset + op->src.offset);
		else
			regs[CFI_FP].offset += op->src.offset;
	}

	if (cfa->offset < -regs[CFI_FP].offset)
		regs[CFI_FP].offset = 0;
}

static void do_stack_ops(struct instruction *insn, struct insn_state *state)
{
	struct stack_op *op;

	list_for_each_entry(op, &insn->stack_ops, list) {
		update_cfi_state(&state->cfi, op);
	}
}

static void walk_code(struct objtool_file *file, struct section *sec,
		      struct symbol *func,
		      struct instruction *insn, struct insn_state *state)
{
	struct symbol *insn_func = insn->func;
	struct instruction *dest;
	struct cfi_state save_cfi;
	unsigned long start, end;

	for (; insn; insn = next_insn_same_sec(file, insn)) {

		if (insn->func != insn_func)
			return;

		if (insn->cfi) {
			if (fill) {
				/* CFI is present. Nothing to fill. */
				return;
			}
			if (insn->cfi->regs[CFI_FP].offset ||
			    !state->cfi.regs[CFI_FP].offset) {
				return;
			}
			/*
			 * The new CFI contains a valid frame and the existing
			 * CFI doesn't. Replace the existing CFI with the new
			 * one.
			 */
		}
		insn->cfi = cfi_hash_find_or_add(&state->cfi);
		dest = insn->jump_dest;

		do_stack_ops(insn, state);

		switch (insn->type) {
		case INSN_BUG:
		case INSN_RETURN:
		case INSN_UNRELIABLE:
			return;

		case INSN_CALL:
		case INSN_CALL_DYNAMIC:
			start = func->offset;
			end = start + func->len;
			/*
			 * Treat intra-function calls as jumps and fall
			 * through.
			 */
			if (!dest || dest->sec != sec ||
			    dest->offset <= start || dest->offset >= end) {
				break;
			}
			/* fallthrough */

		case INSN_JUMP_UNCONDITIONAL:
		case INSN_JUMP_CONDITIONAL:
		case INSN_JUMP_DYNAMIC:
			if (dest) {
				save_cfi = state->cfi;
				walk_code(file, sec, func, dest, state);
				state->cfi = save_cfi;
			}
			if (insn->type == INSN_JUMP_UNCONDITIONAL ||
			    insn->type == INSN_JUMP_DYNAMIC) {
				return;
			}
			break;

		default:
			break;
		}
	}
}

static void walk_function(struct objtool_file *file, struct section *sec,
			  struct symbol *func)
{
	struct instruction *insn = find_insn(file, sec, func->offset);
	struct insn_state state;

	init_insn_state(&state, sec);
	set_func_state(&state.cfi);

	walk_code(file, sec, func, insn, &state);
}

/*
 * This function addresses cases like jump tables where there is an array
 * of unconditional branches. The normal walk would not have visited these
 * instructions and established CFIs for them. Find those instructions. For
 * each such instruction, copy the CFI from the branch instruction and
 * propagate it down.
 */
static void fill_function(struct objtool_file *file, struct section *sec,
			  struct symbol *func)
{
	struct instruction *insn, *prev;
	struct insn_state state;

	func_for_each_insn(file, func, insn) {

		if (insn->cfi) {
			/* Instruction already has a CFI. */
			continue;
		}

		prev = list_prev_entry(insn, list);
		if (!prev || !prev->cfi) {
			/*
			 * Previous instruction does not have a CFI that can
			 * be used for this instruction.
			 */
			continue;
		}

		if (prev->type != INSN_JUMP_UNCONDITIONAL &&
		    prev->type != INSN_JUMP_DYNAMIC) {
			/* Only copy CFI from unconditional branches. */
			continue;
		}

		/*
		 * Propagate the CFI to all the instructions that can be
		 * visited from the current instruction that don't already
		 * have a CFI.
		 */
		state.cfi = *prev->cfi;
		walk_code(file, insn->sec, insn->func, insn, &state);
	}
}

static void walk_section(struct objtool_file *file, struct section *sec)
{
	struct symbol *func;

	list_for_each_entry(func, &sec->symbol_list, list) {

		if (func->type != STT_FUNC || !func->len ||
		    func->pfunc != func || func->alias != func) {
			/* No CFI generated for this function. */
			continue;
		}

		if (!fill)
			walk_function(file, sec, func);
		else
			fill_function(file, sec, func);
	}
}

static void walk_sections(struct objtool_file *file)
{
	struct section *sec;

	for_each_sec(file, sec) {
		if (sec->sh.sh_flags & SHF_EXECINSTR)
			walk_section(file, sec);
	}
}

int fpv_decode(struct objtool_file *file)
{
	int ret;

	arch_initial_func_cfi_state(&initial_func_cfi);

	if (!cfi_hash_alloc(1UL << (file->elf->symbol_bits - 3)))
		return -1;

	ret = decode_instructions(file);
	if (ret)
		return ret;

	add_jump_destinations(file);

	ret = read_unwind_hints(file);
	if (ret)
		return ret;

	if (!list_empty(&file->insn_list)) {
		fill = false;
		walk_sections(file);
		fill = true;
		walk_sections(file);
	}

	return 0;
}
