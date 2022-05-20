// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */
#include <linux/objtool.h>

#include <objtool/builtin.h>
#include <objtool/insn.h>
#include <objtool/warn.h>

static unsigned long nr_insns;

/*
 * Call the arch-specific instruction decoder for all the instructions and add
 * them to the global instruction list.
 */
int decode_instructions(struct objtool_file *file)
{
	struct section *sec;
	struct symbol *func;
	unsigned long offset;
	struct instruction *insn;
	int ret;

	for_each_sec(file, sec) {

		if (!(sec->sh.sh_flags & SHF_EXECINSTR))
			continue;

		if (strcmp(sec->name, ".altinstr_replacement") &&
		    strcmp(sec->name, ".altinstr_aux") &&
		    strncmp(sec->name, ".discard.", 9))
			sec->text = true;

		if (!strcmp(sec->name, ".noinstr.text") ||
		    !strcmp(sec->name, ".entry.text"))
			sec->noinstr = true;

		for (offset = 0; offset < sec->sh.sh_size; offset += insn->len) {
			insn = malloc(sizeof(*insn));
			if (!insn) {
				WARN("malloc failed");
				return -1;
			}
			memset(insn, 0, sizeof(*insn));
			INIT_LIST_HEAD(&insn->alts);
			INIT_LIST_HEAD(&insn->stack_ops);
			INIT_LIST_HEAD(&insn->call_node);

			insn->sec = sec;
			insn->offset = offset;

			ret = arch_decode_instruction(file, sec, offset,
						      sec->sh.sh_size - offset,
						      &insn->len, &insn->type,
						      &insn->immediate,
						      &insn->stack_ops);
			if (ret)
				goto err;

			/*
			 * By default, "ud2" is a dead end unless otherwise
			 * annotated, because GCC 7 inserts it for certain
			 * divide-by-zero cases.
			 */
			if (insn->type == INSN_BUG)
				insn->dead_end = true;

			hash_add(file->insn_hash, &insn->hash, sec_offset_hash(sec, insn->offset));
			list_add_tail(&insn->list, &file->insn_list);
			nr_insns++;
		}

		list_for_each_entry(func, &sec->symbol_list, list) {
			if (func->type != STT_FUNC || func->alias != func)
				continue;

			if (!find_insn(file, sec, func->offset)) {
				WARN("%s(): can't find starting instruction",
				     func->name);
				return -1;
			}

			sym_for_each_insn(file, func, insn) {
				insn->func = func;
				if (insn->type == INSN_ENDBR && list_empty(&insn->call_node)) {
					if (insn->offset == insn->func->offset) {
						list_add_tail(&insn->call_node, &file->endbr_list);
						file->nr_endbr++;
					} else {
						file->nr_endbr_int++;
					}
				}
			}
		}
	}

	if (stats)
		printf("nr_insns: %lu\n", nr_insns);

	return 0;

err:
	free(insn);
	return ret;
}
