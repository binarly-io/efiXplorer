// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2020-2026 Binarly

#pragma once

#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include <allins.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <frame.hpp>
#include <graph.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <pro.h>
#if IDA_SDK_VERSION < 850
#include <struct.hpp>
#endif
#include <typeinf.hpp>
#ifdef HEX_RAYS
#include <hexrays.hpp>
#endif

#include <json.hpp>

using nlohmann::json;

#define COPYRIGHT                                                              \
  "(C) 2020-2025  Binarly - https://github.com/binarly-io/efiXplorer"

#define BTOA(x) ((x) ? "true" : "false")

constexpr uint16_t VZ = 0x5A56;
constexpr uint16_t MZ = 0x5A4D;

constexpr uint32_t BS_OFFSET_64 = 0x60;
constexpr uint32_t BS_OFFSET_32 = 0x3c;
constexpr uint32_t RT_OFFSET_64 = 0x58;
constexpr uint32_t RT_OFFSET_32 = 0x38;

constexpr uint16_t NONE_REG = 0xffff;
constexpr uint16_t NONE_OFFSET = 0xffff;
constexpr uint16_t NONE_PUSH = 0xffff;

enum class analysis_kind_t { unsupported, x86_32, x86_64, aarch64, uefi };
enum class ffs_file_type_t {
  unsupported = 0,
  peim = 6,
  driver = 7,
  mm_standalone = 14
};

enum class module_type_t { dxe_smm = 0, pei = 1, standalone_smm = 2 };

enum machine_type_t { AMD64 = 0x8664, I386 = 0x014C, AARCH64 = 0xaa64 };

enum regs_x86_32_t {
  R_EAX,
  R_ECX,
  R_EDX,
  R_EBX,
  R_ESP,
  R_EBP,
  R_ESI,
  R_EDI,
  R_AL = 0x10,
  R_DL = 0x12
};

enum regs_x86_64_t {
  R_RAX,
  R_RCX,
  R_RDX,
  R_RBX,
  R_RSP,
  R_RBP,
  R_RSI,
  R_RDI,
  R_R8,
  R_R9,
  R_R10,
  R_R11,
  R_R12,
  R_R13,
  R_R14,
};

enum regs_aarch64_t {
  R_C0 = 0,
  R_C13 = 13,
  R_X0 = 129,
  R_X1,
  R_X2,
  R_X3,
  R_X4,
  R_X5,
  R_X6,
  R_X7,
  R_X8,
  R_X9,
  R_X10,
  R_X11,
  R_X12,
  R_X13,
  R_X14,
  R_X15,
  R_X16,
  R_X17,
  R_X18,
  R_X19,
  R_X20,
  R_X21,
  R_X22,
  R_X23,
  R_X24,
  R_X25,
  R_X26,
  R_X27,
  R_X28,
  R_X29,
  R_X30,
  R_XZR,
  R_XSP,
  R_XPC,
};

struct service_info_64_t {
  char name[64];
  uint32_t offset;
  uint32_t reg;
  uint16_t arg_index;
};

struct service_info_32_t {
  char name[64];
  uint32_t offset;
  uint16_t push_number;
};

struct service_t {
  char name[64];
  uint32_t offset64;
  uint32_t offset32;
};

using ea_list_t = std::vector<ea_t>;
using ea_set_t = std::set<ea_t>;
using func_list_t = std::vector<func_t *>;
using json_list_t = std::vector<json>;
using segment_list_t = std::vector<segment_t *>;
using string_list_t = std::vector<std::string>;
using string_set_t = std::set<std::string>;
using uchar_list_t = std::vector<uchar>;
using uint64_list_t = std::vector<uint64_t>;
using uint8_list_t = std::vector<uint8_t>;

struct efi_guid_t {
  uint32_t data1;
  uint16_t data2;
  uint16_t data3;
  uint8_t data4[8];

  uchar_list_t uchar_data() {
    uchar_list_t res;
    res.push_back(data1 & 0xff);
    res.push_back(data1 >> 8 & 0xff);
    res.push_back(data1 >> 16 & 0xff);
    res.push_back(data1 >> 24 & 0xff);
    res.push_back(data2 & 0xff);
    res.push_back(data2 >> 8 & 0xff);
    res.push_back(data3 & 0xff);
    res.push_back(data3 >> 8 & 0xff);
    for (const auto &byte : data4) {
      res.push_back(byte);
    }
    return res;
  }

  std::string to_string() const {
    char guid_str[37] = {};
    snprintf(guid_str, sizeof(guid_str),
             "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", data1, data2,
             data3, data4[0], data4[1], data4[2], data4[3], data4[4], data4[5],
             data4[6], data4[7]);
    return guid_str;
  }
};

extern service_info_64_t g_boot_services_table_aarch64[];
extern size_t g_boot_services_table_aarch64_count;

extern service_info_64_t g_boot_services_table64[];
extern size_t g_boot_services_table64_count;

extern service_info_32_t g_boot_services_table32[];
extern size_t g_boot_services_table32_count;

extern service_t g_boot_services_table_all[];
extern size_t g_boot_services_table_all_count;

extern service_t g_runtime_services_table_all[];
extern size_t g_runtime_services_table_all_count;

extern service_info_64_t g_smm_services_prot64[];
extern size_t g_smm_services_prot64_count;

extern service_t g_smm_services_table_all[];
extern size_t g_smm_services_table_all_count;

extern service_info_32_t g_pei_services_table32[];
extern size_t g_pei_services_table32_count;

extern service_t g_pei_services_table_all[];
extern size_t g_pei_services_table_all_count;

extern service_t g_variable_ppi_table_all[];
extern size_t g_variable_ppi_table_all_count;

extern const char *g_plugin_name;
