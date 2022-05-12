// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Author: Madhavan T. Venkataraman (madvenka@linux.microsoft.com)
 *
 * Copyright (C) 2022 Microsoft Corporation
 */

/*
 * objtool fp validation:
 *
 * This command analyzes a .o file and adds .orc_unwind and .orc_unwind_ip
 * sections to it. The sections are used by the frame pointer-based in-kernel
 * unwinder to validate the frame pointer.
 */

#include <string.h>
#include <objtool/builtin.h>
#include <objtool/objtool.h>

static const char * const fpv_usage[] = {
	"objtool fpv generate file.o",
	"objtool fpv dump file.o",
	NULL,
};

const struct option fpv_options[] = {
	OPT_END(),
};

int cmd_fpv(int argc, const char **argv)
{
	const char *objname;
	struct objtool_file *file;
	int ret;

	argc--; argv++;
	if (argc <= 0)
		usage_with_options(fpv_usage, fpv_options);

	objname = argv[1];

	file = objtool_open_read(objname);
	if (!file)
		return 1;

	/* Supported architectures. */
	switch (file->elf->ehdr.e_machine) {
	case EM_AARCH64:
		break;

	default:
		return 1;
	}

	if (!strncmp(argv[0], "gen", 3)) {
		ret = fpv_decode(file);
		if (ret)
			return ret;

		if (list_empty(&file->insn_list))
			return 0;

		ret = orc_create(file);
		if (ret)
			return ret;

		if (!file->elf->changed)
			return 0;

		return elf_write(file->elf);
	}

	if (!strcmp(argv[0], "dump"))
		return orc_dump(objname);

	usage_with_options(fpv_usage, fpv_options);

	return 0;
}
