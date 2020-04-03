#include "fort.h"
#include "json.hpp"
#include <auto.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <filesystem>
#include <fstream>
#include <ida.hpp>
#include <idp.hpp>
#include <iostream>
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

/* max address */
#define MAX_ADDR 0xffffffffffffffff

/* SystemTable->BootServices */
#define BS_OFFSET 0x60
/* SystemTable->RuntimeServices */
#define RS_OFFSET 0x58

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

#define REG_NONE_64 0xffff

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

#define x64InstallProtocolInterfaceOffset 0x80
#define x64RenstallProtocolInterfaceOffset 0x88
#define x64UninstallProtocolInterfaceOffset 0x90
#define x64HandleProtocolOffset 0x98
#define x64RegisterProtocolNotifyOffset 0xa8
#define x64OpenProtocolOffset 0x118
#define x64CloseProtocolOffset 0x120
#define x64OpenProtocolInformationOffset 0x128
#define x64ProtocolsPerHandleOffset 0x130
#define x64LocateHandleBufferOffset 0x138
#define x64LocateProtocolOffset 0x140
#define x64InstallMultipleProtocolInterfacesOffset 0x148
#define x64UninstallMultipleProtocolInterfacesOffset 0x150

#define x86InstallProtocolInterfaceOffset 0x4c
#define x86RenstallProtocolInterfaceOffset 0x50
#define x86UninstallProtocolInterfaceOffset 0x54
#define x86HandleProtocolOffset 0x58
#define x86RegisterProtocolNotifyOffset 0x60
#define x86OpenProtocolOffset 0x98
#define x86CloseProtocolOffset 0x9c
#define x86OpenProtocolInformationOffset 0xa0
#define x86ProtocolsPerHandleOffset 0xa4
#define x86LocateHandleBufferOffset 0xa8
#define x86LocateProtocolOffset 0xac
#define x86InstallMultipleProtocolInterfacesOffset 0xb0
#define x86UninstallMultipleProtocolInterfacesOffset 0xb4

void setGuidStructure(ea_t ea);
uint8_t getFileType();
