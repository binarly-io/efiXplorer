/*
 * ______________________.___
 * \_   _____/\_   _____/|   |
 *  |    __)_  |    __)  |   |
 *  |        \ |     \   |   |
 * /_______  / \___  /   |___|
 *         \/      \/
 *   _________       .__                 ____  __.      .__  _____
 *  /   _____/_  _  _|__| ______ _____  |    |/ _| ____ |__|/ ____\____
 *  \_____  \\ \/ \/ /  |/  ___//  ___/ |      <  /    \|  \   __\/ __ \
 *  /        \\     /|  |\___ \ \___ \  |    |  \|   |  \  ||  | \  ___/
 * /_______  / \/\_/ |__/____  >____  > |____|__ \___|  /__||__|  \___  >
 *         \/                \/     \/          \/    \/              \/
 *
 * EFI Swiss Knife
 * An IDA plugin to improve (U)EFI reversing
 *
 * Copyright (C) 2016, 2017  Pedro Vilaça (fG!) - reverser@put.as -
 * https://reverse.put.as
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * efi_system_tables.h
 *
 */

#include "stdint.h"

struct pei_services_entry {
    char name[256];
    uint32_t offset;
    char description[1024];
    uint32_t nr_args;
    char prototype[512];
    uint32_t count;
};

struct pei_services_entry pei_services_table[] = {
    {"InstallPpi", 0x18,
     "This service is the first one provided by the PEI Foundation. This "
     "function installs an interface in the PEI PPI database by GUID. The "
     "purpose of the service is to publish an interface that other parties can "
     "use to call additional PEIMs.",
     2,
     "EFI_STATUS(EFIAPI * EFI_PEI_INSTALL_PPI) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN CONST EFI_PEI_PPI_DESCRIPTOR *PpiList)",
     0},
    {"ReInstallPpi", 0x1C,
     "This function reinstalls an interface in the PEI PPI database by GUID. "
     "The purpose of the service is to publish an interface that other parties "
     "can use to replace a same-named interface in the protocol database with "
     "a different interface.",
     3,
     "EFI_STATUS(EFIAPI * EFI_PEI_REINSTALL_PPI) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN CONST EFI_PEI_PPI_DESCRIPTOR *OldPpi, IN CONST "
     "EFI_PEI_PPI_DESCRIPTOR *NewPpi)",
     0},
    {"LocatePpi", 0x20,
     "This function locates an interface in the PEI PPI database by GUID.", 5,
     "EFI_STATUS(EFIAPI * EFI_PEI_LOCATE_PPI) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN CONST EFI_GUID *Guid, IN UINTN Instance, IN OUT "
     "EFI_PEI_PPI_DESCRIPTOR **PpiDescriptor OPTIONAL, IN OUT VOID **Ppi)",
     0},
    {"NotifyPpi", 0x24,
     "This function installs a notification service to be called back when a "
     "given interface is installed or reinstalled. The purpose of the service "
     "is to publish an interface that other parties can use to call additional "
     "PPIs that may materialize later.",
     2,
     "EFI_STATUS(EFIAPI * EFI_PEI_NOTIFY_PPI) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN CONST EFI_PEI_NOTIFY_DESCRIPTOR *NotifyList)",
     0},
    {"GetBootMode", 0x28,
     "This function returns the present value of the boot mode.", 2,
     "EFI_STATUS(EFIAPI * EFI_PEI_GET_BOOT_MODE) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, OUT EFI_BOOT_MODE *BootMode)",
     0},
    {"SetBootMode", 0x2C, "This function sets the value of the boot mode.", 2,
     "EFI_STATUS(EFIAPI * EFI_PEI_SET_BOOT_MODE) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN EFI_BOOT_MODE BootMode)",
     0},
    {"GetHobList", 0x30,
     "This function returns the pointer to the list of Hand-Off Blocks (HOBs) "
     "in memory.",
     2,
     "EFI_STATUS(EFIAPI * EFI_PEI_GET_HOB_LIST) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, OUT VOID **HobList)",
     0},
    {"CreateHob", 0x34,
     "This service, published by the PEI Foundation, abstracts the creation of "
     "a Hand-Off Block's (HOB's) headers.",
     4,
     "EFI_STATUS(EFIAPI * EFI_PEI_CREATE_HOB) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN UINT16 Type, IN UINT16 Length, IN OUT VOID **Hob)",
     0},
    {"FfsFindNextVolume", 0x38,
     "The purpose of the service is to abstract the capability of the PEI "
     "Foundation to discover instances of firmware volumes in the system. "
     "Given the input file pointer, this service searches for the next "
     "matching file in the Firmware File System (FFS) volume.",
     3,
     "EFI_STATUS (EFIAPI *EFI_PEI_FFS_FIND_NEXT_VOLUME) (IN struct "
     "_EFI_PEI_SERVICES **PeiServices, IN UINTN Instance, IN OUT "
     "EFI_FIRMWARE_VOLUME_HEADER **FwVolHeader)",
     0},
    {"FfsFindNextFile", 0x3C,
     "The purpose of the service is to abstract the capability of the PEI "
     "Foundation to discover instances of firmware files in the system. Given "
     "the input file pointer, this service searches for the next matching file "
     "in the Firmware File System (FFS) volume.",
     4,
     "EFI_STATUS (EFIAPI *EFI_PEI_FFS_FIND_NEXT_FILE) (IN struct "
     "_EFI_PEI_SERVICES **PeiServices, IN EFI_FV_FILETYPE SearchType, IN "
     "EFI_FIRMWARE_VOLUME_HEADER *FwVolHeader, IN OUT EFI_FFS_FILE_HEADER "
     "**FileHeader);",
     0},
    {"FfsFindSectionData", 0x40,
     "Given the input file pointer, this service searches for the next "
     "matching file in the Firmware File System (FFS) volume.",
     4,
     "EFI_STATUS (EFIAPI *EFI_PEI_FFS_FIND_SECTION_DATA) (IN struct "
     "_EFI_PEI_SERVICES **PeiServices, IN EFI_SECTION_TYPE SectionType, IN "
     "EFI_FFS_FILE_HEADER *FfsFileHeader, IN OUT VOID **SectionData);",
     0},
    {"InstallPeiMemory", 0x44,
     "This function registers the found memory configuration with the PEI "
     "Foundation.",
     3,
     "EFI_STATUS(EFIAPI * EFI_PEI_INSTALL_PEI_MEMORY) (IN CONST "
     "EFI_PEI_SERVICES **PeiServices, IN EFI_PHYSICAL_ADDRESS MemoryBegin, IN "
     "UINT64 MemoryLength)",
     0},
    {"AllocatePages", 0x48,
     "The purpose of the service is to publish an interface that allows PEIMs "
     "to allocate memory ranges that are managed by the PEI Foundation.",
     4,
     "EFI_STATUS(EFIAPI * EFI_PEI_ALLOCATE_PAGES) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN EFI_MEMORY_TYPE MemoryType, IN UINTN Pages, OUT "
     "EFI_PHYSICAL_ADDRESS *Memory)",
     0},
    {"AllocatePool", 0x4C,
     "The purpose of this service is to publish an interface that allows PEIMs "
     "to allocate memory ranges that are managed by the PEI Foundation.",
     3,
     " EFI_STATUS(EFIAPI * EFI_PEI_ALLOCATE_POOL) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices, IN UINTN Size, OUT VOID **Buffer)",
     0},
    {"CopyMem", 0x50,
     "This service copies the contents of one buffer to another buffer.", 3,
     "VOID(EFIAPI * EFI_PEI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, "
     "IN UINTN Length)",
     0},
    {"SetMem", 0x54, "The service fills a buffer with a specified value.", 3,
     "VOID(EFIAPI * EFI_PEI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 "
     "Value)",
     0},
    {"ReportStatusCode", 0x58,
     "This service publishes an interface that allows PEIMs to report status codes. \
        ReportStatusCode() is called by PEIMs that wish to report status information on their progress. The principal use model is for a PEIM to emit one of the standard 32-bit error codes. This will allow a platform owner to ascertain the state of the system, especially under conditions where the full consoles might not have been installed.",
     6,
     "EFI_STATUS(EFIAPI * EFI_PEI_REPORT_STATUS_CODE) (IN CONST "
     "EFI_PEI_SERVICES **PeiServices, IN EFI_STATUS_CODE_TYPE Type, IN "
     "EFI_STATUS_CODE_VALUE Value, IN UINT32 Instance, IN CONST EFI_GUID "
     "*CallerId OPTIONAL, IN CONST EFI_STATUS_CODE_DATA *Data OPTIONAL)",
     0},
    {"ResetSystem", 0x5C, "Resets the entire platform. \
        This service resets the entire platform, including all processors and devices, and reboots the system. This service will never return EFI_SUCCESS.",
     1,
     "EFI_STATUS(EFIAPI * EFI_PEI_RESET_SYSTEM) (IN CONST EFI_PEI_SERVICES "
     "**PeiServices)",
     0},
    {"CpuIo", 0x60,
     "Provides an interface that a PEIM can call to execute an I/O "
     "transaction. This service is installed by an architectural PEI driver by "
     "copying the interface pointer into this table.",
     1, "", 0},
    {"PciCfg", 0x64,
     "Provides an interface that a PEIM can call to execute PCI Configuration "
     "transactions. This service is installed by an architectural PEI driver "
     "by copying the interface pointer into this table.",
     1, "", 0}};

size_t pei_services_table_size =
    sizeof(pei_services_table) / sizeof(pei_services_entry);
