/* efiSmmUtils.h
 * This file is part of efiXplorer
 */

#include "efiUtils.h"

struct efiGuid {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

func_t *findSmiHandlerCpuProtocol();
func_t *findSmiHandlerSmmSwDispatch();
