/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */

#ifndef _INSN_H
#define _INSN_H

#include <objtool/objtool.h>
#include <objtool/arch.h>

struct insn_state {
	struct cfi_state cfi;
	unsigned int uaccess_stack;
	bool uaccess;
	bool df;
	bool noinstr;
	s8 instr;
};

struct instruction {
	struct list_head list;
	struct hlist_node hash;
	struct list_head call_node;
	struct section *sec;
	unsigned long offset;
	unsigned int len;
	enum insn_type type;
	unsigned long immediate;

	u8 dead_end	: 1,
	   ignore	: 1,
	   ignore_alts	: 1,
	   hint		: 1,
	   retpoline_safe : 1,
	   noendbr	: 1;
		/* 2 bit hole */
	s8 instr;
	u8 visited;
	/* u8 hole */

	struct alt_group *alt_group;
	struct symbol *call_dest;
	struct instruction *jump_dest;
	struct instruction *first_jump_src;
	struct reloc *jump_table;
	struct reloc *reloc;
	struct list_head alts;
	struct symbol *func;
	struct list_head stack_ops;
	struct cfi_state *cfi;
};

static inline bool is_static_jump(struct instruction *insn)
{
	return insn->type == INSN_JUMP_CONDITIONAL ||
	       insn->type == INSN_JUMP_UNCONDITIONAL;
}

static inline bool is_dynamic_jump(struct instruction *insn)
{
	return insn->type == INSN_JUMP_DYNAMIC ||
	       insn->type == INSN_JUMP_DYNAMIC_CONDITIONAL;
}

static inline bool is_jump(struct instruction *insn)
{
	return is_static_jump(insn) || is_dynamic_jump(insn);
}

void init_insn_state(struct insn_state *state, struct section *sec);
struct instruction *find_insn(struct objtool_file *file,
			      struct section *sec, unsigned long offset);
struct instruction *find_last_insn(struct objtool_file *file,
				   struct section *sec);
struct instruction *prev_insn_same_sym(struct objtool_file *file,
				       struct instruction *insn);
struct instruction *next_insn_same_sec(struct objtool_file *file,
				       struct instruction *insn);
struct instruction *next_insn_same_func(struct objtool_file *file,
					struct instruction *insn);
struct reloc *insn_reloc(struct objtool_file *file, struct instruction *insn);
bool insn_can_reloc(struct instruction *insn);
bool insn_cfi_match(struct instruction *insn, struct cfi_state *cfi2);
bool same_function(struct instruction *insn1, struct instruction *insn2);
bool is_first_func_insn(struct instruction *insn);
int decode_instructions(struct objtool_file *file);
int read_unwind_hints(struct objtool_file *file);


#define for_each_insn(file, insn)					\
	list_for_each_entry(insn, &file->insn_list, list)

#define sec_for_each_insn(file, sec, insn)				\
	for (insn = find_insn(file, sec, 0);				\
	     insn && &insn->list != &file->insn_list &&			\
			insn->sec == sec;				\
	     insn = list_next_entry(insn, list))

#define func_for_each_insn(file, func, insn)				\
	for (insn = find_insn(file, func->sec, func->offset);		\
	     insn;							\
	     insn = next_insn_same_func(file, insn))

#define sym_for_each_insn(file, sym, insn)				\
	for (insn = find_insn(file, sym->sec, sym->offset);		\
	     insn && &insn->list != &file->insn_list &&			\
		insn->sec == sym->sec &&				\
		insn->offset < sym->offset + sym->len;			\
	     insn = list_next_entry(insn, list))

#define sym_for_each_insn_continue_reverse(file, sym, insn)		\
	for (insn = list_prev_entry(insn, list);			\
	     &insn->list != &file->insn_list &&				\
		insn->sec == sym->sec && insn->offset >= sym->offset;	\
	     insn = list_prev_entry(insn, list))

#define sec_for_each_insn_from(file, insn)				\
	for (; insn; insn = next_insn_same_sec(file, insn))

#define sec_for_each_insn_continue(file, insn)				\
	for (insn = next_insn_same_sec(file, insn); insn;		\
	     insn = next_insn_same_sec(file, insn))

#endif /* _INSN_H */
