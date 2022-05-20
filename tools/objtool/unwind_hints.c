// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015-2017 Josh Poimboeuf <jpoimboe@redhat.com>
 */
#include <asm/unwind_hints.h>

#include <objtool/builtin.h>
#include <objtool/endianness.h>
#include <objtool/insn.h>
#include <objtool/warn.h>

int read_unwind_hints(struct objtool_file *file)
{
	struct cfi_state cfi = init_cfi;
	struct section *sec, *relocsec;
	struct unwind_hint *hint;
	struct instruction *insn;
	struct reloc *reloc;
	int i;

	sec = find_section_by_name(file->elf, ".discard.unwind_hints");
	if (!sec)
		return 0;

	relocsec = sec->reloc;
	if (!relocsec) {
		WARN("missing .rela.discard.unwind_hints section");
		return -1;
	}

	if (sec->sh.sh_size % sizeof(struct unwind_hint)) {
		WARN("struct unwind_hint size mismatch");
		return -1;
	}

	file->hints = true;

	for (i = 0; i < sec->sh.sh_size / sizeof(struct unwind_hint); i++) {
		hint = (struct unwind_hint *)sec->data->d_buf + i;

		reloc = find_reloc_by_dest(file->elf, sec, i * sizeof(*hint));
		if (!reloc) {
			WARN("can't find reloc for unwind_hints[%d]", i);
			return -1;
		}

		insn = find_insn(file, reloc->sym->sec, reloc->addend);
		if (!insn) {
			WARN("can't find insn for unwind_hints[%d]", i);
			return -1;
		}

		insn->hint = true;

		if (ibt && hint->type == UNWIND_HINT_TYPE_REGS_PARTIAL) {
			struct symbol *sym = find_symbol_by_offset(insn->sec, insn->offset);

			if (sym && sym->bind == STB_GLOBAL &&
			    insn->type != INSN_ENDBR && !insn->noendbr) {
				WARN_FUNC("UNWIND_HINT_IRET_REGS without ENDBR",
					  insn->sec, insn->offset);
			}
		}

		if (hint->type == UNWIND_HINT_TYPE_FUNC) {
			insn->cfi = &func_cfi;
			continue;
		}

		if (insn->cfi)
			cfi = *(insn->cfi);

		if (arch_decode_hint_reg(hint->sp_reg, &cfi.cfa.base)) {
			WARN_FUNC("unsupported unwind_hint sp base reg %d",
				  insn->sec, insn->offset, hint->sp_reg);
			return -1;
		}

		cfi.cfa.offset = bswap_if_needed(hint->sp_offset);
		cfi.type = hint->type;
		cfi.end = hint->end;

		insn->cfi = cfi_hash_find_or_add(&cfi);
	}

	return 0;
}
