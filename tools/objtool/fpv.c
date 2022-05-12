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

int fpv_decode(struct objtool_file *file)
{
	int ret;

	ret = decode_instructions(file);
	if (ret)
		return ret;

	add_jump_destinations(file);

	return 0;
}
