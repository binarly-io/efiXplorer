/*
 * efiXplorer
 * Copyright (C) 2020-2025 Binarly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

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
