/*
 * efiXplorer
 * Copyright (C) 2020-2024 Binarly
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

#include "efi_defs.h"
#include <string>

arch_file_type_t input_file_type();

bool add_struct_for_shifted_ptr();
bool addr_in_tables(ea_list_t t1, ea_list_t t2, ea_t ea);
bool addr_in_tables(ea_list_t t1, ea_list_t t2, ea_list_t t3, ea_t ea);
bool addr_in_vec(ea_list_t vec, ea_t addr);
bool check_boot_service_protocol_xrefs(ea_t call_addr);
bool check_boot_service_protocol(ea_t call_addr);
bool check_install_protocol(ea_t ea);
bool json_in_vec(json_list_t vec, json item);
bool mark_copies_for_gvars(ea_list_t gvars, std::string type);
bool op_stroff_util(ea_t addr, std::string type);
bool set_ptr_type(ea_t addr, std::string type);
bool set_ret_to_pei_svc(ea_t start_ea);
bool summary_json_exists();
bool uint64_in_vec(uint64_list_t vec, uint64_t value);
bool valid_guid(json guid);

ea_t find_unknown_bs_var_64(ea_t ea);

efi_guid_t get_global_guid(ea_t addr);
efi_guid_t get_local_guid(func_t *f, uint64_t offset);

ffs_file_type_t ask_file_type(json_list_t *m_all_guids);

json get_guid_by_address(ea_t addr);

qstring get_module_name_loader(ea_t addr);

std::filesystem::path get_guids_json_file();
std::filesystem::path get_summary_file();

std::string as_hex(uint64_t value);
std::string get_table_name(std::string service_name);
std::string get_wide_string(ea_t addr);
std::string guid_to_string(json guid);
std::string lookup_boot_service_name(uint64_t offset);
std::string lookup_runtime_service_name(uint64_t offset);
std::string type_to_name(std::string type);

ea_list_t find_data(ea_t start_ea, ea_t end_ea, uchar *data, size_t len);
ea_list_t get_xrefs_to_array(ea_t addr);
ea_list_t get_xrefs_util(ea_t addr);
ea_list_t search_protocol(std::string protocol);

uint16_t get_machine_type();
uint32_t u32_addr(ea_t addr);
uint64_t u64_addr(ea_t addr);

uint8_list_t unpack_guid(std::string guid);

uval_t trunc_imm_to_dtype(uval_t value, op_dtype_t dtype);

void op_stroff_for_global_interface(ea_list_t xrefs, qstring type_name);
void op_stroff_for_interface(xreflist_t local_xrefs, qstring type_name);
void set_const_char16_type(ea_t ea);
void set_entry_arg_to_pei_svc();
void set_guid_type(ea_t ea);
void set_ptr_type_and_name(ea_t ea, std::string name, std::string type);
void set_type_and_name(ea_t ea, std::string name, std::string type);

xreflist_t xrefs_to_stack_var(ea_t func_addr, qstring var_name);

#if IDA_SDK_VERSION >= 900
tid_t import_type(const til_t *til, int _idx, const char *name);
#endif
