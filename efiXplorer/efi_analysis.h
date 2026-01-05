// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include "efi_defs.h"
#include "efi_smm_utils.h"
#include "efi_utils.h"
#ifdef HEX_RAYS
#include "efi_hexrays.h"
#endif
#include <map>
#include <string>

namespace efi_analysis {

class efi_analyser_t {
public:
  efi_analyser_t();
  ~efi_analyser_t();

  ea_set_t m_bs_list;   // gBS list (boot services addresses)
  ea_set_t m_rt_list;   // gRT list (runtime services addresses)
  ea_set_t m_smst_list; // gSmst list (SMM system table addresses)
  ea_set_t m_st_list;   // gST list (system table addresses)

  ea_set_t m_funcs;

  func_list_t m_smi_handlers;
  json_list_t m_all_guids;
  json_list_t m_all_ppis;
  json_list_t m_all_protocols;
  json_list_t m_all_services;
  json_list_t m_nvram_variables;

  // all .text and .data segments
  // for compatibility with the efixloader
  segment_list_t m_code_segs;
  segment_list_t m_data_segs;

  analysis_kind_t m_analysis_kind = analysis_kind_t::unsupported;
  ffs_file_type_t m_ftype = ffs_file_type_t::unsupported;

  void dump_json();
  void get_segments();
  void set_pvalues();
  void annotate_protocol_guids();
  void annotate_data_guids();
  bool smm_cpu_protocol_resolver();
  void find_smi_handlers();
  bool analyse_nvram_variables();

protected:
  ea_t m_start_addr = 0;
  ea_t m_end_addr = 0;

  // a map to look up a GUID name by value
  std::map<json, std::string> m_guiddb_map;
  json m_guiddb;

  std::filesystem::path m_guids_json_path;

  // protocol related boot services
  string_list_t m_prot_bs_names = {"InstallProtocolInterface",
                                   "ReinstallProtocolInterface",
                                   "UninstallProtocolInterface",
                                   "HandleProtocol",
                                   "RegisterProtocolNotify",
                                   "OpenProtocol",
                                   "CloseProtocol",
                                   "OpenProtocolInformation",
                                   "ProtocolsPerHandle",
                                   "LocateHandleBuffer",
                                   "LocateProtocol",
                                   "InstallMultipleProtocolInterfaces",
                                   "UninstallMultipleProtocolInterfaces"};

  // protocol related SMM services
  string_list_t m_prot_smms_names = {"SmmInstallProtocolInterface",
                                     "SmmUninstallProtocolInterface",
                                     "SmmHandleProtocol",
                                     "SmmRegisterProtocolNotify",
                                     "SmmLocateHandle",
                                     "SmmLocateProtocol"};

  // protocol related PEI services
  string_list_t m_ppi_peis_names = {"InstallPpi", "ReInstallPpi", "LocatePpi",
                                    "NotifyPpi"};

  // data and stack guids
  json_list_t m_data_guids;
  json_list_t m_stack_guids;

  ea_set_t m_annotated_protocols;
  json m_boot_services;
  json m_pei_services_all;
  json m_ppi_calls_all;
  json m_runtime_services_all;
  json m_smm_services_all;
  json m_smm_services;

  ea_set_t m_image_handle_list; // gImageHandle list (image handle addresses)
  ea_set_t m_runtime_services_list; // runtime services list

  // for SMM callout scanners
  ea_set_t m_callout_addrs;
  ea_set_t m_read_save_state_calls;
  func_list_t m_child_smi_handlers;
  func_list_t m_exc_funcs;

  // for double GetVariable scanners
  ea_set_t m_double_get_variable_pei;
  ea_set_t m_double_get_variable_smm;
  ea_set_t m_double_get_variable;

  tid_t m_macro_efi_tid;
  tid_t m_macro_var_attr_tid;

  // mask and masked value for MACRO_EFI enum value detection
  uint64_t m_mask = 0;
  uint64_t m_masked_value = 0;

  bool add_protocol(std::string service_name, ea_t guid_addr, ea_t xref_addr,
                    ea_t call_addr);

private:
  // format dependent settings
  // protocols for DXE/SMM PPIs for PEI
  json_list_t *m_ptable;
  std::string m_pname;
  std::string m_pkey;

  uint64_list_t m_ppi_flags = {
      0x1,        0x10,       0x11,       0x20,       0x21,       0x30,
      0x31,       0x40,       0x41,       0x50,       0x51,       0x60,
      0x61,       0x70,       0x71,       0x80000000, 0x80000001, 0x80000010,
      0x80000011, 0x80000020, 0x80000021, 0x80000030, 0x80000031, 0x80000040,
      0x80000041, 0x80000050, 0x80000051, 0x80000060, 0x80000061, 0x80000070,
      0x80000071,
  };

  // EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_sw_guid2 = {0x18a3c6dc,
                           0x5eea,
                           0x48c8,
                           {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99}};
  // EFI_SMM_SW_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_sw_guid = {0xe541b773,
                          0xdd11,
                          0x420c,
                          {0xb0, 0x26, 0xdf, 0x99, 0x36, 0x53, 0xf8, 0xbf}};
  // EFI_SMM_SX_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_sx_guid2 = {0x456d2859,
                           0xa84b,
                           0x4e47,
                           {0xa2, 0xee, 0x32, 0x76, 0xd8, 0x86, 0x99, 0x7d}};
  // EFI_SMM_SX_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_sx_guid = {0x14FC52BE,
                          0x01DC,
                          0x426C,
                          {0x91, 0xAE, 0xA2, 0x3C, 0x3E, 0x22, 0x0A, 0xE8}};
  // EFI_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_io_trap_guid2 = {
      0x58DC368D,
      0x7BFA,
      0x4E77,
      {0xAB, 0xBC, 0x0E, 0x29, 0x41, 0x8D, 0xF9, 0x30}};
  // EFI_SMM_IO_TRAP_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_io_trap_guid = {
      0xDB7F536B,
      0xEDE4,
      0x4714,
      {0xA5, 0xC8, 0xE3, 0x46, 0xEB, 0xAA, 0x20, 0x1D}};
  // EFI_SMM_GPI_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_gpi_guid2 = {0x25566B03,
                            0xB577,
                            0x4CBF,
                            {0x95, 0x8C, 0xED, 0x66, 0x3E, 0xA2, 0x43, 0x80}};
  // EFI_SMM_GPI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_gpi_guid = {0xE0744B81,
                           0x9513,
                           0x49CD,
                           {0x8C, 0xEA, 0xE9, 0x24, 0x5E, 0x70, 0x39, 0xDA}};
  // EFI_SMM_USB_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_usb_guid2 = {0xEE9B8D90,
                            0xC5A6,
                            0x40A2,
                            {0xBD, 0xE2, 0x52, 0x55, 0x8D, 0x33, 0xCC, 0xA1}};
  // EFI_SMM_USB_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_usb_guid = {0xA05B6FFD,
                           0x87AF,
                           0x4E42,
                           {0x95, 0xC9, 0x62, 0x28, 0xB6, 0x3C, 0xF3, 0xF3}};
  // EFI_SMM_STANDBY_BUTTON_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_standby_button_guid2 = {
      0x7300C4A1,
      0x43F2,
      0x4017,
      {0xA5, 0x1B, 0xC8, 0x1A, 0x7F, 0x40, 0x58, 0x5B}};
  // EFI_SMM_STANDBY_BUTTON_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_standby_button_guid = {
      0x78965B98,
      0xB0BF,
      0x449E,
      {0x8B, 0x22, 0xD2, 0x91, 0x4E, 0x49, 0x8A, 0x98}};
  // EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_periodic_timer_guid2 = {
      0x4CEC368E,
      0x8E8E,
      0x4D71,
      {0x8B, 0xE1, 0x95, 0x8C, 0x45, 0xFC, 0x8A, 0x53}};
  // EFI_SMM_PERIODIC_TIMER_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_periodic_timer_guid = {
      0x9CCA03FC,
      0x4C9E,
      0x4A19,
      {0x9B, 0x06, 0xED, 0x7B, 0x47, 0x9B, 0xDE, 0x55}};
  // EFI_SMM_POWER_BUTTON_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_power_button_guid2 = {
      0x1B1183FA,
      0x1823,
      0x46A7,
      {0x88, 0x72, 0x9C, 0x57, 0x87, 0x55, 0x40, 0x9D}};
  // EFI_SMM_POWER_BUTTON_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_power_button_guid = {
      0xB709EFA0,
      0x47A6,
      0x4B41,
      {0xB9, 0x31, 0x12, 0xEC, 0xE7, 0xA8, 0xEE, 0x56}};
  // EFI_SMM_ICHN_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_ichn_guid = {0xC50B323E,
                            0x9075,
                            0x4F2A,
                            {0xAC, 0x8E, 0xD2, 0x59, 0x6A, 0x10, 0x85, 0xCC}};
  // EFI_SMM_ICHN_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_ichn_guid2 = {0xADF3A128,
                             0x416D,
                             0x4060,
                             {0x8D, 0xDF, 0x30, 0xA1, 0xD7, 0xAA, 0xB6, 0x99}};
  // PCH_TCO_SMI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_tco_guid = {0x9E71D609,
                           0x6D24,
                           0x47FD,
                           {0xB5, 0x72, 0x61, 0x40, 0xF8, 0xD9, 0xC2, 0xA4}};
  // PCH_PCIE_SMI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_pcie_guid = {0x3E7D2B56,
                            0x3F47,
                            0x42AA,
                            {0x8F, 0x6B, 0x22, 0xF5, 0x19, 0x81, 0x8D, 0xAB}};
  // PCH_ACPI_SMI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_acpi_guid = {0xD52BB262,
                            0xF022,
                            0x49EC,
                            {0x86, 0xD2, 0x7A, 0x29, 0x3A, 0x7A, 0x5, 0x4B}};
  // PCH_GPIO_UNLOCK_SMI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_gpio_unlock_guid = {
      0x83339EF7,
      0x9392,
      0x4716,
      {0x8D, 0x3A, 0xD1, 0xFC, 0x67, 0xCD, 0x55, 0xDB}};
  // PCH_SMI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_pch_guid = {0xE6A81BBF,
                           0x873D,
                           0x47FD,
                           {0xB6, 0xBE, 0x61, 0xB3, 0xE5, 0x72, 0x9, 0x93}};
  // PCH_ESPI_SMI_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_espi_guid = {0xB3C14FF3,
                            0xBAE8,
                            0x456C,
                            {0x86, 0x31, 0x27, 0xFE, 0x0C, 0xEB, 0x34, 0x0C}};
  // EFI_ACPI_EN_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_acpi_en_guid = {
      0xBD88EC68,
      0xEBE4,
      0x4F7B,
      {0x93, 0x5A, 0x4F, 0x66, 0x66, 0x42, 0xE7, 0x5F}};
  // EFI_ACPI_DIS_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_acpi_dis_guid = {
      0x9C939BA6,
      0x1FCC,
      0x46F6,
      {0xB4, 0xE1, 0x10, 0x2D, 0xBE, 0x18, 0x65, 0x67}};
  // FCH_SMM_GPI_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_gpi_guid2 = {
      0x7051ab6d,
      0x9ec2,
      0x42eb,
      {0xa2, 0x13, 0xde, 0x48, 0x81, 0xf1, 0xf7, 0x87}};
  // FCH_SMM_IO_TRAP_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_io_trap_guid2 = {
      0x91288fc4,
      0xe64b,
      0x4ef9,
      {0xa4, 0x63, 0x66, 0x88, 0x0, 0x71, 0x7f, 0xca}};
  // FCH_SMM_PERIODICAL_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_periodical_guid2 = {
      0x736102f1,
      0x9584,
      0x44e7,
      {0x82, 0x8a, 0x43, 0x4b, 0x1e, 0x67, 0x5c, 0xc4}};
  // FCH_SMM_PWR_BTN_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_pwr_btn_guid2 = {
      0xa365240e,
      0x56b0,
      0x426d,
      {0x83, 0xa, 0x30, 0x66, 0xc6, 0x81, 0xbe, 0x9a}};
  // FCH_SMM_SW_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_sw_guid2 = {
      0x881b4ab6,
      0x17b0,
      0x4bdf,
      {0x88, 0xe2, 0xd4, 0x29, 0xda, 0x42, 0x5f, 0xfd}};
  // FCH_SMM_SX_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_sx_guid2 = {
      0x87e2a6cf,
      0x91fb,
      0x4581,
      {0x90, 0xa9, 0x6f, 0x50, 0x5d, 0xdc, 0x1c, 0xb2}};
  // FCH_SMM_USB_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_fch_usb_guid = {0x59053b0d,
                               0xeeb8,
                               0x4379,
                               {0xb1, 0xc8, 0x14, 0x5f, 0x1b, 0xb, 0xe4, 0xb9}};
  // FCH_SMM_USB_DISPATCH2_PROTOCOL_GUID
  efi_guid_t m_fch_usb_guid2 = {
      0xfbbb2ea9,
      0xce0e,
      0x4689,
      {0xb3, 0xf0, 0xc6, 0xb8, 0xf0, 0x76, 0xbd, 0x20}};
  // FCH_SMM_MISC_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_fch_misc_guid = {
      0x13bd659b,
      0xb4c6,
      0x47da,
      {0x9b, 0x22, 0x11, 0x50, 0xd4, 0xf3, 0xb, 0xda}};
  // FCH_SMM_APU_RAS_DISPATCH_PROTOCOL_GUID
  efi_guid_t m_fch_apu_ras_guid = {
      0xf871ee59,
      0x29d2,
      0x4b15,
      {0x9e, 0x67, 0xaf, 0x32, 0xcd, 0xc1, 0x41, 0x73}};

  void print_interfaces();
  bool analyse_variable_service(ea_t ea, std::string service_str);
};

class efi_analyser_x86_t : public efi_analyser_t {
public:
  efi_analyser_x86_t() : efi_analyser_t() {
    // import necessary types
    const til_t *idati = get_idati();
    import_type(idati, -1, "EFI_GUID");
    import_type(idati, -1, "EFI_HANDLE");
    import_type(idati, -1, "EFI_SYSTEM_TABLE");
    import_type(idati, -1, "EFI_BOOT_SERVICES");
    import_type(idati, -1, "EFI_RUNTIME_SERVICES");
    import_type(idati, -1, "_EFI_SMM_SYSTEM_TABLE2");
    import_type(idati, -1, "EFI_PEI_SERVICES");
    import_type(idati, -1, "EFI_PEI_READ_ONLY_VARIABLE2_PPI");
    import_type(idati, -1, "EFI_SMM_VARIABLE_PROTOCOL");
    m_macro_efi_tid = import_type(idati, -1, "MACRO_EFI");
    m_macro_var_attr_tid = import_type(idati, -1, "MACRO_VARIABLE_ATTRIBUTE");

#ifdef HEX_RAYS
    for (auto idx = 0; idx < get_entry_qty(); idx++) {
      uval_t ord = get_entry_ordinal(idx);
      ea_t ep = get_entry(ord);
      efi_hexrays::propagate_types(get_func(ep), 0);
    }
#endif
  }

  bool find_boot_services_tables();
  bool find_double_get_variable_pei();
  bool find_double_get_variable_smm();
  bool find_double_get_variable();
  bool find_image_handle64();
  bool find_runtime_services_tables();
  bool find_smm_callout();
  bool find_smst_postproc64();
  bool find_smst64();
  bool find_system_table64();
  void find_local_guids64();
  void find_other_boot_services_tables64();
  void get_boot_services_all();
  void get_bs_prot_names32();
  void get_bs_prot_names64();
  void get_pei_services_all32();
  void get_ppi_names32();
  void get_prot_boot_services32();
  void get_prot_boot_services64();
  void get_runtime_services_all();
  void get_smm_prot_names64();
  void get_smm_services_all64();
  void get_variable_ppi_calls_all32();
  void set_operands_repr();
  void show_all_choosers();

private:
  bool install_multiple_prot_interfaces_analyser();
  bool set_enums_repr(ea_t ea, insn_t insn);
  void find_callout_rec(func_t *func);
};

class efi_analyser_arm_t : public efi_analyser_t {
public:
  efi_analyser_arm_t() : efi_analyser_t() {
    // in order to make it work, it is necessary to copy
    // uefi.til, uefi64.til files in {idadir}/til/arm/
    add_til("uefi64.til", ADDTIL_DEFAULT);

    const til_t *idati = get_idati();
    import_type(idati, -1, "EFI_BOOT_SERVICES");
    import_type(idati, -1, "EFI_GUID");
    import_type(idati, -1, "EFI_HANDLE");
    import_type(idati, -1, "EFI_RUNTIME_SERVICES");
    import_type(idati, -1, "EFI_SYSTEM_TABLE");
    m_macro_efi_tid = import_type(idati, -1, "MACRO_EFI");
    m_macro_var_attr_tid = import_type(idati, -1, "MACRO_VARIABLE_ATTRIBUTE");
  }

  ~efi_analyser_arm_t() {
    m_image_handle_list.clear();
    m_st_list_arm.clear();
    m_bs_list_arm.clear();
    m_rt_list_arm.clear();
  }

  void detect_protocols_all();
  void detect_services_all();
  void find_boot_services_tables();
  void find_pei_services_function();
  void initial_analysis();
  void initial_gvars_detection();
  void set_operands_repr();
  void show_all_choosers();

private:
  ea_set_t m_image_handle_list_arm;
  ea_set_t m_st_list_arm;
  ea_set_t m_bs_list_arm;
  ea_set_t m_rt_list_arm;

  tid_t m_macro_efi_tid;
  tid_t m_macro_var_attr_tid;

  bool get_protocol(ea_t address, uint32_t p_reg, std::string service_name);
  bool set_enums_repr(ea_t ea, insn_t insn);
  bool set_offsets_repr(ea_t ea, insn_t insn);
};

bool efi_analyse_main_x86_64();
bool efi_analyse_main_x86_32();
bool efi_analyse_main_aarch64();
}; // namespace efi_analysis
