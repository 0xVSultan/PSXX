/* The host programs (the tests, the command line tools) have the English tables of the texts known before main: the core asks for its texts by identifier (core/tr.h). The tests of the
 * screens clear the ranges that the console does not have in RAM at that point (tests/test_screens_a.c, test_screens_b.c). */
#include "ui_text.h"
#include "ui_ids.h"

__attribute__((constructor)) static void ui_autoreg(void)
{
	ui_reg_a();
	ui_reg_b();
	ui_reg_l();
}
