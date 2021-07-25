/*
 * efiXplorer
 * Copyright (C) 2020-2021 Binarly
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

/* 3rd party */
#include "json.hpp"

#include <algorithm>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <filesystem>
#include <fstream>
#include <graph.hpp>
#include <hexrays.hpp>
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

using namespace nlohmann;

/* undefine to hide debug messages */
#define DEBUG

#ifdef DEBUG
#define DEBUG_MSG(format, ...) msg(format, ##__VA_ARGS__);
#else
#define DEBUG_MSG(format, ...) {};
#endif

#define BTOA(x) ((x) ? "true" : "false")

/* architectures */
#define X86 32
#define X64 64
#define UEFI 96

/* (FFS) file type */
#define FTYPE_DXE_AND_THE_LIKE 7
#define FTYPE_PEI 6

#define VZ 0x5A56
#define MZ 0x5A4D

/* SystemTable->BootServices */
#define BS_OFFSET_X64 0x60
#define BS_OFFSET_X86 0x3c

/* SystemTable->RuntimeServices */
#define RT_OFFSET_X64 0x58
#define RT_OFFSET_X86 0x38

/* x64 registers */
#define REG_RAX 0x00
#define REG_RCX 0x01
#define REG_RDX 0x02
#define REG_RBX 0x03
#define REG_RSP 0x04
#define REG_RBP 0x05
#define REG_RSI 0x06
#define REG_RDI 0x07
#define REG_R8 0x08
#define REG_R9 0x09
#define REG_R10 0x0a
#define REG_R11 0x0b
#define REG_R12 0x0c
#define REG_R13 0x0d
#define REG_R14 0x0e

/* x86 registers */
#define REG_EAX 0x00
#define REG_ECX 0x01
#define REG_EDX 0x02
#define REG_EBX 0x03
#define REG_ESP 0x04
#define REG_EBP 0x05
#define REG_ESI 0x06
#define REG_EDI 0x07
#define REG_AL 0x10
#define REG_DL 0x12

#define PUSH_NONE 0xffff
#define GUID_OFFSET_NONE 0xffff
#define GUID_OFFSET_DWORD 4

/* allins.h */
#define NN_call 16
#define NN_callni 18
#define NN_lea 92
#define NN_mov 122
#define NN_push 143
#define NN_retn 159

/* Get input file type
 * (64-bit, 32-bit image or UEFI firmware) */
uint8_t getArch();

/* Get image type (PEI or DXE-like) */
uint8_t getFileType(std::vector<json> *allGuids);

/* Set EFI_GUID type */
void setGuidType(ea_t ea);

/* Get all data xrefs for address */
std::vector<ea_t> getXrefs(ea_t addr);

/* op_stroff wrapper */
bool opStroff(ea_t addr, std::string type);

/* Create EFI_GUID structure */
void createGuidStructure(ea_t ea);

/* Get boot service description comment */
std::string getBsComment(ea_t offset, uint8_t arch);

/* Get PEI service description comment (X86 is assumed) */
std::string getPeiSvcComment(ea_t offset);
std::string getPPICallComment(ea_t offset, std::string name);

/* Get SMM service description comment */
std::string getSmmVarComment();

/* Get runtime service description comment */
std::string getRtComment(ea_t offset, uint8_t arch);

/* Find address of global gBS variable
 * for X64 module for each service */
ea_t findUnknownBsVarX64(ea_t ea);

/* Get pointer to named type and apply it */
bool setPtrType(ea_t addr, std::string type);

/* Set name and apply pointer to named type */
void setPtrTypeAndName(ea_t ea, std::string name, std::string type);

/* Check for guids.json file exist */
bool guidsJsonExists();

/* Get json summary file name */
std::filesystem::path getSummaryFile();

/* Check for summary json file exist */
bool summaryJsonExist();

/* Change EFI_SYSTEM_TABLE *SystemTable to EFI_PEI_SERVICES **PeiService
/* for ModuleEntryPoint */
void setEntryArgToPeiSvc();

/* Set type and name */
void setTypeAndName(ea_t ea, std::string name, std::string type);

/* Collect information for dependency browser and dependency graph */
std::vector<json> getDependenciesLoader();

/* Get name for each node */
std::vector<std::string> getNodes(std::vector<json> depJson);

/* Get edges */
std::vector<json> getEdges(std::vector<std::string> depNodes, std::vector<json> depJson);

/* Get module name by address */
qstring getModuleNameLoader(ea_t address);

/* Print std::vector<json> object */
void printVectorJson(std::vector<json> in);

/* Change the value of a number to match the data type */
uval_t truncImmToDtype(uval_t value, op_dtype_t dtype);

/* Get GUID data by address */
json getGuidByAddr(ea_t addr);

/* Validate GUID value */
bool checkGuid(json guid);
