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

int fpv_decode(struct objtool_file *file)
{
	return decode_instructions(file);
}
