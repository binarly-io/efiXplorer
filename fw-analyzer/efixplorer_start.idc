/* efixplorer_start.idc
 * This file is part of efiXplorer
 */

#include <idc.idc>

static main() {
  set_inf_attr(INF_AF, get_inf_attr(INF_AF) | AF_DODATA | AF_FINAL);
  auto_mark_range(0, BADADDR, AU_FINAL);
  auto_wait();
  RunPlugin("efiXplorer", 0);
  qexit(0);
}
