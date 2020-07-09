/*
 *        __ ___   __      _
 *       / _(_) \ / /     | |
 *   ___| |_ _ \ V / _ __ | | ___  _ __ ___ _ __
 *  / _ \  _| | > < | '_ \| |/ _ \| '__/ _ \ '__|
 * |  __/ | | |/ . \| |_) | | (_) | | |  __/ |
 *  \___|_| |_/_/ \_\ .__/|_|\___/|_|  \___|_|
 *                  | |
 *                  |_|
 *
 * efiXplorer
 * Copyright (C) 2020  Binarly
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
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * efiUtils.h
 *
 */

#define _CRT_SECURE_NO_WARNINGS

#include "fort.h"
#include "json.hpp"
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <filesystem>
#include <fstream>
#include <ida.hpp>
#include <idp.hpp>
#include <iostream>
#include <kernwin.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <stdio.h>
#include <string>
#include <struct.hpp>
#include <typeinf.hpp>

using namespace nlohmann;
using namespace std;
using namespace std::filesystem;

/* undefine to hide debug messages */
#define DEBUG

#ifdef DEBUG
#define DEBUG_MSG(format, ...) msg(format, ##__VA_ARGS__);
#else
#define DEBUG_MSG(format, ...) {};
#endif

/* architectures */
#define X86 32
#define X64 64

/* SystemTable->BootServices */
#define BS_OFFSET 0x60
/* SystemTable->RuntimeServices */
#define RT_OFFSET 0x58

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

/* allins.h */
#define NN_call 16
#define NN_callni 18
#define NN_lea 92
#define NN_mov 122
#define NN_push 143
#define NN_retn 159

uint8_t getFileType();
void setGuidType(ea_t ea);
void setBsTypeAndName(ea_t ea, string name);
void setRtTypeAndName(ea_t ea, string name);
void setSmstTypeAndName(ea_t ea, string name);
string getBsComment(ea_t offset, size_t arch);
string getRtComment(ea_t offset, size_t arch);
vector<ea_t> getXrefs(ea_t addr);
ea_t findUnknownBsVarX64(ea_t ea);
