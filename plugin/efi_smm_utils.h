// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include "efi_utils.h"
#include <string>

namespace efi_smm_utils {
func_list_t find_smi_handlers(ea_t address, std::string prefix);
func_list_t find_smi_handlers_dispatch(efi_guid_t guid, std::string prefix);
func_list_t find_smi_handlers_dispatch_stack(json_list_t stack_guids,
                                             std::string prefix);
ea_set_t find_smst_sw_dispatch(const ea_set_t &bs_list);
ea_set_t find_smst_smm_base(const ea_set_t &bs_list);
ea_set_t find_smm_get_variable_calls(segment_list_t data_segs,
                                     json_list_t *all_services);
ea_set_t resolve_efi_smm_cpu_protocol(json_list_t stack_guids,
                                      json_list_t data_guids,
                                      json_list_t *all_services);
ea_t mark_child_sw_smi_handlers(ea_t ea);
} // namespace efi_smm_utils
