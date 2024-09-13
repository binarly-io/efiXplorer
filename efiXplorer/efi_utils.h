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
 * efiUtils.h
 *
 */

#pragma once

// 3rd party
#include "json.hpp"

#include <algorithm>
#include <allins.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <filesystem>
#include <frame.hpp>
#include <fstream>
#include <graph.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <iostream>
#include <kernwin.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <pro.h>
#include <stdio.h>
#include <string>
#if IDA_SDK_VERSION < 900
#include <struct.hpp>
#endif
#include <typeinf.hpp>

#ifdef HEX_RAYS
#include <hexrays.hpp>
#endif

#include "efi_defs.h"

using namespace nlohmann;

struct EfiGuid {
  uint32_t data1;
  uint16_t data2;
  uint16_t data3;
  uint8_t data4[8];
  std::vector<uchar> uchar_data() {
    std::vector<uchar> res;
    res.push_back(data1 & 0xff);
    res.push_back(data1 >> 8 & 0xff);
    res.push_back(data1 >> 16 & 0xff);
    res.push_back(data1 >> 24 & 0xff);
    res.push_back(data2 & 0xff);
    res.push_back(data2 >> 8 & 0xff);
    res.push_back(data3 & 0xff);
    res.push_back(data3 >> 8 & 0xff);
    for (auto i = 0; i < 8; i++) {
      res.push_back(data4[i]);
    }
    return res;
  }
  std::string to_string() {
    char res[37] = {0};
    snprintf(res, 37, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", data1, data2,
             data3, data4[0], data4[1], data4[2], data4[3], data4[4], data4[5], data4[6],
             data4[7]);
    return static_cast<std::string>(res);
  }
};

ArchFileType input_file_type();
FfsFileType ask_file_type(std::vector<json> *all_guids);

// Set EFI_GUID type
void setGuidType(ea_t ea);

// Get all data xrefs for address
std::vector<ea_t> getXrefs(ea_t addr);
std::vector<ea_t> getXrefsToArray(ea_t addr);

// Wrapper for op_stroff function
bool opStroff(ea_t addr, std::string type);

// Find address of global gBS variable
// for X64 module for each service
ea_t findUnknownBsVarX64(ea_t ea);

// Get pointer to named type and apply it
bool setPtrType(ea_t addr, std::string type);

// Set name and apply pointer to named type
void setPtrTypeAndName(ea_t ea, std::string name, std::string type);

// Get guids.json file name
std::filesystem::path getGuidsJsonFile();

// Get json summary file name
std::filesystem::path getSummaryFile();

// Check for summary json file exist
bool summaryJsonExist();

// Change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
// for ModuleEntryPoint
void setEntryArgToPeiSvc();

// Set return value type to EFI_PEI_SERVICES **PeiService
// for specified function
bool setRetToPeiSvc(ea_t start_ea);

// Set type and name
void setTypeAndName(ea_t ea, std::string name, std::string type);

// Set const CHAR16 type
void setConstChar16Type(ea_t ea);

// Get module name by address
qstring getModuleNameLoader(ea_t address);

// Print std::vector<json> object
void printVectorJson(std::vector<json> in);

// Change the value of a number to match the data type
uval_t truncImmToDtype(uval_t value, op_dtype_t dtype);

// Get GUID data by address
json getGuidByAddr(ea_t addr);

// Validate GUID value
bool checkGuid(json guid);

// Make sure the first argument looks like protocol
bool bootServiceProtCheck(ea_t callAddr);

// Make sure that the address does not belong to the protocol interface
bool bootServiceProtCheckXrefs(ea_t callAddr);

// Convert GUID value to string
std::string getGuidFromValue(json guid);

// Convert string GUID to vector of bytes
std::vector<uint8_t> unpackGuid(std::string guid);

// Convert 64-bit value to hex string
std::string getHex(uint64_t value);

// Mark copies for global variables
bool markCopiesForGlobalVars(std::vector<ea_t> globalVars, std::string type);

//  Generate name string from type
std::string typeToName(std::string type);

// Get XREFs to stack variable
xreflist_t xrefsToStackVar(ea_t funcEa, qstring varName);

// Mark the arguments of each function from an interface derived from a local variable
void opstroffForInterface(xreflist_t localXrefs, qstring typeName);

// Mark the arguments of each function from an interface derived from a global variable
void opstroffForGlobalInterface(std::vector<ea_t> xrefs, qstring typeName);

// Find wrappers
bool qwordInVec(std::vector<uint64_t> vec, uint64_t value);
bool addrInVec(std::vector<ea_t> vec, ea_t addr);
bool jsonInVec(std::vector<json> vec, json item);
bool addrInTables(std::vector<ea_t> gStList, std::vector<ea_t> gBsList,
                  std::vector<ea_t> gRtList, ea_t ea);

// Search protocol GUID bytes in binary
std::vector<ea_t> searchProtocol(std::string protocol);

bool checkInstallProtocol(ea_t ea);
std::vector<ea_t> findData(ea_t start_ea, ea_t end_ea, uchar *data, size_t len);
std::string getWideString(ea_t addr);
EfiGuid getGlobalGuid(ea_t addr);
EfiGuid getStackGuid(func_t *f, uint64_t offset);
bool addStrucForShiftedPtr();
std::string getTable(std::string service_name);
std::string lookupBootServiceName(uint64_t offset);
std::string lookupRuntimeServiceName(uint64_t offset);
uint64_t u64_addr(ea_t addr);
uint32_t u32_addr(ea_t addr);
uint16_t get_machine_type();

#if IDA_SDK_VERSION >= 900
tid_t import_type(const til_t *til, int _idx, const char *name);
#endif
