// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#include <string.h>

#include <objtool/builtin.h>
#include <objtool/insn.h>
#include <objtool/warn.h>

struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset)
{
	struct instruction *insn;

	offset -= sec->sh.sh_addr;
	hash_for_each_possible(file->insn_hash, insn, hash, sec_offset_hash(sec, offset)) {
		if (insn->sec == sec && insn->offset == offset)
			return insn;
	}

	return NULL;
}

struct instruction *next_insn_same_sec(struct objtool_file *file,
				       struct instruction *insn)
{
	struct instruction *next = list_next_entry(insn, list);

	if (!next || &next->list == &file->insn_list || next->sec != insn->sec)
		return NULL;

	return next;
}

struct instruction *next_insn_same_func(struct objtool_file *file,
					struct instruction *insn)
{
	struct instruction *next = list_next_entry(insn, list);
	struct symbol *func = insn->func;

	if (!func)
		return NULL;

	if (&next->list != &file->insn_list && next->func == func)
		return next;

	/* Check if we're already in the subfunction: */
	if (func == func->cfunc)
		return NULL;

	/* Move to the subfunction: */
	return find_insn(file, func->cfunc->sec, func->cfunc->offset);
}

struct instruction *prev_insn_same_sym(struct objtool_file *file,
				       struct instruction *insn)
{
	struct instruction *prev = list_prev_entry(insn, list);

	if (&prev->list != &file->insn_list && prev->func == insn->func)
		return prev;

	return NULL;
}

struct instruction *find_last_insn(struct objtool_file *file,
				   struct section *sec)
{
	struct instruction *insn = NULL;
	unsigned int offset;
	unsigned int end = (sec->sh.sh_size > 10) ? sec->sh.sh_size - 10 : 0;

	for (offset = sec->sh.sh_size - 1; offset >= end && !insn; offset--)
		insn = find_insn(file, sec, offset);

	return insn;
}

bool same_function(struct instruction *insn1, struct instruction *insn2)
{
	return insn1->func->pfunc == insn2->func->pfunc;
}

bool is_first_func_insn(struct instruction *insn)
{
	return insn->offset == insn->func->offset ||
	       (insn->type == INSN_ENDBR &&
		insn->offset == insn->func->offset + insn->len);
}

bool insn_cfi_match(struct instruction *insn, struct cfi_state *cfi2)
{
	struct cfi_state *cfi1 = insn->cfi;
	int i;

	if (!cfi1) {
		WARN("CFI missing");
		return false;
	}

	if (memcmp(&cfi1->cfa, &cfi2->cfa, sizeof(cfi1->cfa))) {

		WARN_FUNC("stack state mismatch: cfa1=%d%+d cfa2=%d%+d",
			  insn->sec, insn->offset,
			  cfi1->cfa.base, cfi1->cfa.offset,
			  cfi2->cfa.base, cfi2->cfa.offset);

	} else if (memcmp(&cfi1->regs, &cfi2->regs, sizeof(cfi1->regs))) {
		for (i = 0; i < CFI_NUM_REGS; i++) {
			if (!memcmp(&cfi1->regs[i], &cfi2->regs[i],
				    sizeof(struct cfi_reg)))
				continue;

			WARN_FUNC("stack state mismatch: reg1[%d]=%d%+d reg2[%d]=%d%+d",
				  insn->sec, insn->offset,
				  i, cfi1->regs[i].base, cfi1->regs[i].offset,
				  i, cfi2->regs[i].base, cfi2->regs[i].offset);
			break;
		}

	} else if (cfi1->type != cfi2->type) {

		WARN_FUNC("stack state mismatch: type1=%d type2=%d",
			  insn->sec, insn->offset, cfi1->type, cfi2->type);

	} else if (cfi1->drap != cfi2->drap ||
		   (cfi1->drap && cfi1->drap_reg != cfi2->drap_reg) ||
		   (cfi1->drap && cfi1->drap_offset != cfi2->drap_offset)) {

		WARN_FUNC("stack state mismatch: drap1=%d(%d,%d) drap2=%d(%d,%d)",
			  insn->sec, insn->offset,
			  cfi1->drap, cfi1->drap_reg, cfi1->drap_offset,
			  cfi2->drap, cfi2->drap_reg, cfi2->drap_offset);

	} else
		return true;

	return false;
}

void init_insn_state(struct insn_state *state, struct section *sec)
{
	memset(state, 0, sizeof(*state));
	init_cfi_state(&state->cfi);

	/*
	 * We need the full vmlinux for noinstr validation, otherwise we can
	 * not correctly determine insn->call_dest->sec (external symbols do
	 * not have a section).
	 */
	if (vmlinux && noinstr && sec)
		state->noinstr = sec->noinstr;
}

#define NEGATIVE_RELOC	((void *)-1L)

struct reloc *insn_reloc(struct objtool_file *file, struct instruction *insn)
{
	if (insn->reloc == NEGATIVE_RELOC)
		return NULL;

	if (!insn->reloc) {
		if (!file)
			return NULL;

		insn->reloc = find_reloc_by_dest_range(file->elf, insn->sec,
						       insn->offset, insn->len);
		if (!insn->reloc) {
			insn->reloc = NEGATIVE_RELOC;
			return NULL;
		}
	}

	return insn->reloc;
}
