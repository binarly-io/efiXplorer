/*
 * efiXplorer
 * Copyright (C) 2020-2022 Binarly
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
#include <struct.hpp>
#include <typeinf.hpp>

#ifdef HEX_RAYS
#include <hexrays.hpp>
#endif

using namespace nlohmann;

#define BTOA(x) ((x) ? "true" : "false")

#define VZ 0x5A56
#define MZ 0x5A4D

enum ArchFileType { UNSUPPORTED_TYPE, X86, X64, UEFI, ARM64 };

enum FfsFileType { FTYPE_PEI = 6, FTYPE_DXE_AND_THE_LIKE = 7 };

enum BootServicesOffset { BS_OFFSET_64BIT = 0x60, BS_OFFSET_32BIT = 0x3c };

enum RuntimeServiesOffset { RT_OFFSET_64BIT = 0x58, RT_OFFSET_32BIT = 0x38 };

enum Registers32bit {
    REG_EAX,
    REG_ECX,
    REG_EDX,
    REG_EBX,
    REG_ESP,
    REG_EBP,
    REG_ESI,
    REG_EDI,
    REG_AL = 0x10,
    REG_DL = 0x12
};

enum Registers64bit {
    REG_RAX,
    REG_RCX,
    REG_RDX,
    REG_RBX,
    REG_RSP,
    REG_RBP,
    REG_RSI,
    REG_RDI,
    REG_R8,
    REG_R9,
    REG_R10,
    REG_R11,
    REG_R12,
    REG_R13,
    REG_R14,
};

enum RegistersAarch64 {
    REG_X0 = 129,
    REG_X1,
    REG_X2,
    REG_X3,
    REG_X4,
    REG_X5,
    REG_X6,
    REG_X7,
    REG_X8,
    REG_X9,
    REG_X10,
    REG_X11,
    REG_X12,
    REG_X13,
    REG_X14,
    REG_X15,
    REG_X16,
    REG_X17,
    REG_X18,
    REG_X19,
    REG_X20,
    REG_X21,
    REG_X22,
    REG_X23,
    REG_X24,
    REG_X25,
    REG_X26,
    REG_X27,
    REG_X28,
    REG_X29,
    REG_X30,
    REG_XZR,
    REG_XSP,
    REG_XPC,
};

enum HelperValues {
    GUID_OFFSET_DWORD = 4,
    GUID_OFFSET_NONE = 0xffff,
    PUSH_NONE = 0xffff,
    BAD_REG = 0xffff,
};

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
        snprintf(res, 37, "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", data1,
                 data2, data3, data4[0], data4[1], data4[2], data4[3], data4[4], data4[5],
                 data4[6], data4[7], data4[8]);
        return static_cast<std::string>(res);
    }
};

// Get input file type
// (64-bit, 32-bit image or UEFI firmware)
uint8_t getInputFileType();

// Get image type (PEI or DXE-like)
uint8_t getFileType(std::vector<json> *allGuids);

// Set EFI_GUID type
void setGuidType(ea_t ea);

// Get all data xrefs for address
std::vector<ea_t> getXrefs(ea_t addr);
std::vector<ea_t> getXrefsToArray(ea_t addr);

// Wrapper for op_stroff function
bool opStroff(ea_t addr, std::string type);

// Create EFI_GUID structure
void createGuidStructure(ea_t ea);

// Get boot service description comment
std::string getBsComment(uint32_t offset, uint8_t arch);

// Get PEI service description comment (X86 is assumed)
std::string getPeiSvcComment(uint32_t offset);

// Get PPI service description comment (X86 is assumed)
std::string getPPICallComment(uint32_t offset, std::string name);

// Get SMM service description comment
std::string getSmmVarComment();

// Get runtime service description comment
std::string getRtComment(uint32_t offset, uint8_t arch);

// Find address of global gBS variable
// for X64 module for each service
ea_t findUnknownBsVarX64(ea_t ea);

// Get pointer to named type and apply it
bool setPtrType(ea_t addr, std::string type);

// Set name and apply pointer to named type
void setPtrTypeAndName(ea_t ea, std::string name, std::string type);

// Check for guids.json file exist
bool guidsJsonExists();

// Get guids.json file name
std::filesystem::path getGuidsJsonFile();

// Get json summary file name
std::filesystem::path getSummaryFile();

// Check for summary json file exist
bool summaryJsonExist();

// Change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
// for ModuleEntryPoint
void setEntryArgToPeiSvc();

// Set type and name
void setTypeAndName(ea_t ea, std::string name, std::string type);

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
uint64_t u64_addr(ea_t addr);
