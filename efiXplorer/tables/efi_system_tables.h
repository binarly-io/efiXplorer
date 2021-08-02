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

#define BTABLE_LEN 43
#define RTABLE_LEN 14

struct services_entry {
    char name[256];
    uint32_t offset64;
    uint32_t offset32;
    char description[1024];
    uint32_t nr_args;
    char prototype[512];
    char parameters[2048];
    char rcx_param[256];
    char rdx_param[256];
    char r8_param[256];
    char r9_param[256];
    char stack1_param[256];
    char stack2_param[256];
    char stack3_param[256];
    char stack4_param[256];
    uint32_t count;
};

struct services_entry boot_services_table[] = {
    {"RaiseTPL", 0x18, 0x18,
     "Raises a task's priority level and returns its previous level.", 1,
     "EFI_TPL(EFIAPI * EFI_RAISE_TPL) (IN EFI_TPL NewTpl)",
     "NewTpl   The new task priority level.", "IN EFI_TPL NewTpl", "", "", "", "", "", "",
     "", 0},
    {"RestoreTPL", 0x20, 0x1c, "Restores a task's priority level to its previous value.",
     1, "VOID(EFIAPI * EFI_RESTORE_TPL) (IN EFI_TPL OldTpl)",
     "OldTpl   The previous task priority level to restore.", "IN EFI_TPL OldTpl", "", "",
     "", "", "", "", "", 0},
    {"AllocatePages", 0x28, 0x20, "Allocates memory pages from the system.", 4,
     "EFI_STATUS(EFIAPI * EFI_ALLOCATE_PAGES) (IN EFI_ALLOCATE_TYPE Type, IN "
     "EFI_MEMORY_TYPE MemoryType, IN UINTN Pages, IN OUT EFI_PHYSICAL_ADDRESS "
     "*Memory)",
     "Type         The type of allocation to perform.\n\
MemoryType   The type of memory to allocate.\n\
Pages        The number of contiguous 4 KB pages to allocate.\n\
Memory       The pointer to a physical address. On input, the way in which the address is used depends on the value of Type.",
     "IN EFI_ALLOCATE_TYPE Type", "IN EFI_MEMORY_TYPE MemoryType", "IN UINTN Pages",
     "IN OUT EFI_PHYSICAL_ADDRESS *Memory", "", "", "", "", 0},
    {"FreePages", 0x30, 0x24, "Frees memory pages.", 2,
     "EFI_STATUS(EFIAPI * EFI_FREE_PAGES) (IN EFI_PHYSICAL_ADDRESS Memory, IN "
     "UINTN Pages)",
     "Memory   The base physical address of the pages to be freed.\n\
Pages    The number of contiguous 4 KB pages to free.",
     "IN EFI_PHYSICAL_ADDRESS Memory", "IN UINTN Pages", "", "", "", "", "", "", 0},
    {"GetMemoryMap", 0x38, 0x28, "Returns the current memory map.", 5,
     "EFI_STATUS(EFIAPI * EFI_GET_MEMORY_MAP) (IN OUT UINTN *MemoryMapSize, IN "
     "OUT EFI_MEMORY_DESCRIPTOR *MemoryMap, OUT UINTN *MapKey, OUT UINTN "
     "*DescriptorSize, OUT UINT32 *DescriptorVersion)",
     "MemoryMapSize       A pointer to the size, in bytes, of the MemoryMap buffer. On input, this is the size of the buffer allocated by the caller.\n\
                    On output, it is the size of the buffer returned by the firmware if the buffer was large enough, or the size of the buffer\n\
                    needed to contain the map if the buffer was too small.\n\
MemoryMap           A pointer to the buffer in which firmware places the current memory map.\n\
MapKey              A pointer to the location in which firmware returns the key for the current memory map.\n\
DescriptorSize      A pointer to the location in which firmware returns the size, in bytes, of an individual EFI_MEMORY_DESCRIPTOR.\n\
DescriptorVersion   A pointer to the location in which firmware returns the version number associated with the EFI_MEMORY_DESCRIPTOR.",
     "IN OUT UINTN *MemoryMapSize", "IN OUT EFI_MEMORY_DESCRIPTOR *MemoryMap",
     "OUT UINTN *MapKey", "OUT UINTN *DescriptorSize", "OUT UINT32 *DescriptorVersion",
     "", "", "", 0},
    {"AllocatePool", 0x40, 0x2c, "Allocates pool memory.", 3,
     "EFI_STATUS(EFIAPI * EFI_ALLOCATE_POOL) (IN EFI_MEMORY_TYPE PoolType, IN "
     "UINTN Size, OUT VOID **Buffer)",
     "PoolType   The type of pool to allocate.\n\
Size       The number of bytes to allocate from the pool.\n\
Buffer     A pointer to a pointer to the allocated buffer if the call succeeds; undefined otherwise.",
     "IN EFI_MEMORY_TYPE PoolType", "IN UINTN Size", "OUT VOID **Buffer", "", "", "", "",
     "", 0},
    {"FreePool", 0x48, 0x30, "Returns pool memory to the system.", 1,
     "EFI_STATUS(EFIAPI * EFI_FREE_POOL) (IN VOID *Buffer)",
     "Buffer The pointer to the buffer to free.", "IN VOID *Buffer", "", "", "", "", "",
     "", "", 0},
    {"CreateEvent", 0x50, 0x34, "Creates an event.", 5,
     "EFI_STATUS(EFIAPI * EFI_CREATE_EVENT) (IN UINT32 Type, IN EFI_TPL "
     "NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction, IN VOID *NotifyContext, "
     "OUT EFI_EVENT *Event)",
     "Type             The type of event to create and its mode and attributes.\n\
NotifyTpl        The task priority level of event notifications, if needed.\n\
NotifyFunction   The pointer to the event's notification function, if any.\n\
NotifyContext    The pointer to the notification function's context; corresponds to parameter Context in the notification function.\n\
Event            The pointer to the newly created event if the call succeeds; undefined otherwise.",
     "IN UINT32 Type", "IN EFI_TPL NotifyTpl", "IN EFI_EVENT_NOTIFY NotifyFunction",
     "IN VOID *NotifyContext", "OUT EFI_EVENT *Event", "", "", "", 0},
    {"SetTimer", 0x58, 0x38,
     "Sets the type of timer and the trigger time for a timer event.", 3,
     "EFI_STATUS(EFIAPI * EFI_SET_TIMER) (IN EFI_EVENT Event, IN "
     "EFI_TIMER_DELAY Type, IN UINT64 TriggerTime)",
     "Event         The timer event that is to be signaled at the specified time.\n\
Type          The type of time that is specified in TriggerTime.\n\
TriggerTime   The number of 100ns units until the timer expires. A TriggerTime of 0 is legal. If Type is TimerRelative and TriggerTime is 0, then the timer event will be signaled on the next timer tick. If Type is TimerPeriodic and TriggerTime is 0, then the timer event will be signaled on every timer tick.",
     "IN EFI_EVENT Event", "IN EFI_TIMER_DELAY Type", "IN UINT64 TriggerTime", "", "", "",
     "", "", 0},
    {"WaitForEvent", 0x60, 0x3c, "Stops execution until an event is signaled.", 3,
     "EFI_STATUS(EFIAPI * EFI_WAIT_FOR_EVENT) (IN UINTN NumberOfEvents, IN "
     "EFI_EVENT *Event, OUT UINTN *Index)",
     "NumberOfEvents   The number of events in the Event array.\n\
Event            An array of EFI_EVENT.\n\
Index            The pointer to the index of the event which satisfied the wait condition.",
     "IN UINTN NumberOfEvents", "IN EFI_EVENT *Event", "OUT UINTN *Index", "", "", "", "",
     "", 0},
    {"SignalEvent", 0x68, 0x40, "Signals an event.", 1,
     "EFI_STATUS(EFIAPI * EFI_SIGNAL_EVENT) (IN EFI_EVENT Event)",
     "Event The event to signal.", "IN EFI_EVENT Event", "", "", "", "", "", "", "", 0},
    {"CloseEvent", 0x70, 0x44, "Closes an event.", 1,
     "EFI_STATUS(EFIAPI * EFI_CLOSE_EVENT) (IN EFI_EVENT Event)",
     "Event The event to close.", "IN EFI_EVENT Event", "", "", "", "", "", "", "", 0},
    {"CheckEvent", 0x78, 0x48, "Checks whether an event is in the signaled state.", 1,
     "EFI_STATUS(EFIAPI * EFI_CHECK_EVENT) (IN EFI_EVENT Event)",
     "Event The event to check.", "IN EFI_EVENT Event", "", "", "", "", "", "", "", 0},
    {"InstallProtocolInterface", 0x80, 0x4c,
     "Installs a protocol interface on a device handle. If the handle does not "
     "exist, it is created and added to the list of handles in the system. "
     "InstallMultipleProtocolInterfaces() performs more error checking than "
     "InstallProtocolInterface(), so it is recommended that "
     "InstallMultipleProtocolInterfaces() be used in place of "
     "InstallProtocolInterface()",
     4,
     "EFI_STATUS(EFIAPI * EFI_INSTALL_PROTOCOL_INTERFACE) (IN OUT EFI_HANDLE "
     "*Handle, IN EFI_GUID *Protocol, IN EFI_INTERFACE_TYPE InterfaceType, IN "
     "VOID *Interface)",
     "Handle          A pointer to the EFI_HANDLE on which the interface is to be installed.\n\
Protocol        The numeric ID of the protocol interface.\n\
InterfaceType   Indicates whether Interface is supplied in native form.\n\
Interface       A pointer to the protocol interface.",
     "IN OUT EFI_HANDLE *Handle", "IN EFI_GUID *Protocol",
     "IN EFI_INTERFACE_TYPE InterfaceType", "IN VOID *Interface", "", "", "", "", 0},
    {"ReinstallProtocolInterface", 0x88, 0x50,
     "Reinstalls a protocol interface on a device handle.", 4,
     "EFI_STATUS(EFIAPI * EFI_REINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE "
     "Handle, IN EFI_GUID *Protocol, IN VOID *OldInterface, IN VOID "
     "*NewInterface)",
     "Handle         Handle on which the interface is to be reinstalled.\n\
Protocol       The numeric ID of the interface.\n\
OldInterface   A pointer to the old interface. NULL can be used if a structure is not associated with Protocol.\n\
NewInterface   A pointer to the new interface.",
     "IN EFI_HANDLE Handle", "IN EFI_GUID *Protocol", "IN VOID *OldInterface",
     "IN VOID *NewInterface", "", "", "", "", 0},
    {"UninstallProtocolInterface", 0x90, 0x54,
     "Removes a protocol interface from a device handle. It is recommended "
     "that UninstallMultipleProtocolInterfaces() be used in place of "
     "UninstallProtocolInterface().",
     3,
     "EFI_STATUS(EFIAPI * EFI_UNINSTALL_PROTOCOL_INTERFACE) (IN EFI_HANDLE "
     "Handle, IN EFI_GUID *Protocol, IN VOID *Interface)",
     "Handle      The handle on which the interface was installed.\n\
Protocol    The numeric ID of the interface.\n\
Interface   A pointer to the interface.",
     "IN EFI_HANDLE Handle", "IN EFI_GUID *Protocol", "IN VOID *Interface", "", "", "",
     "", "", 0},
    {"HandleProtocol", 0x98, 0x58,
     "Queries a handle to determine if it supports a specified protocol.", 3,
     "EFI_STATUS(EFIAPI * EFI_HANDLE_PROTOCOL) (IN EFI_HANDLE Handle, IN "
     "EFI_GUID *Protocol, OUT VOID **Interface)",
     "Handle      The handle being queried.\n\
Protocol    The published unique identifier of the protocol.\n\
Interface   Supplies the address where a pointer to the corresponding Protocol Interface is returned.",
     "IN EFI_HANDLE Handle", "IN EFI_GUID *Protocol", "OUT VOID **Interface", "", "", "",
     "", "", 0},
    {"RegisterProtocolNotify", 0xA8, 0x60,
     "Creates an event that is to be signaled whenever an interface is "
     "installed for a specified protocol.",
     3,
     "EFI_STATUS(EFIAPI * EFI_REGISTER_PROTOCOL_NOTIFY) (IN EFI_GUID "
     "*Protocol, IN EFI_EVENT Event, OUT VOID **Registration)",
     "Protocol       The numeric ID of the protocol for which the event is to be registered.\n\
Event          Event that is to be signaled whenever a protocol interface is registered for Protocol.\n\
Registration   A pointer to a memory location to receive the registration value.",
     "IN EFI_GUID *Protocol", "IN EFI_EVENT Event", "OUT VOID **Registration", "", "", "",
     "", "", 0},
    {"LocateHandle", 0xB0, 0x64,
     "Returns an array of handles that support a specified protocol.", 5,
     "EFI_STATUS(EFIAPI * EFI_LOCATE_HANDLE) (IN EFI_LOCATE_SEARCH_TYPE "
     "SearchType, IN EFI_GUID *Protocol, OPTIONAL IN VOID *SearchKey, OPTIONAL "
     "IN OUT UINTN *BufferSize, OUT EFI_HANDLE *Buffer)",
     "SearchType   Specifies which handle(s) are to be returned.\n\
Protocol     Specifies the protocol to search by.\n\
SearchKey    Specifies the search key.\n\
BufferSize   On input, the size in bytes of Buffer. On output, the size in bytes of the array returned in Buffer (if the buffer was large enough) or the size, in bytes, of the buffer needed to obtain the array (if the buffer was not large enough).\n\
Buffer       The buffer in which the array is returned.",
     "IN EFI_LOCATE_SEARCH_TYPE SearchType", "IN EFI_GUID *Protocol",
     "OPTIONAL IN VOID *SearchKey", "OPTIONAL IN OUT UINTN *BufferSize",
     "OUT EFI_HANDLE *Buffer", "", "", "", 0},
    {"LocateDevicePath", 0xB8, 0x68,
     "Locates the handle to a device on the device path that supports the "
     "specified protocol.",
     3,
     "EFI_STATUS(EFIAPI * EFI_LOCATE_DEVICE_PATH) (IN EFI_GUID *Protocol, IN "
     "OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath, OUT EFI_HANDLE *Device)",
     "Protocol     Specifies the protocol to search for.\n\
DevicePath   On input, a pointer to a pointer to the device path. On output, the device path pointer is modified to point to the remaining part of the device path.\n\
Device       A pointer to the returned device handle.",
     "IN EFI_GUID *Protocol", "IN OUT EFI_DEVICE_PATH_PROTOCOL **DevicePath",
     "OUT EFI_HANDLE *Device", "", "", "", "", "", 0},
    {"InstallConfigurationTable", 0xC0, 0x6c,
     "Adds, updates, or removes a configuration table entry from the EFI "
     "System Table.",
     2,
     "EFI_STATUS(EFIAPI * EFI_INSTALL_CONFIGURATION_TABLE) (IN EFI_GUID *Guid, "
     "IN VOID *Table)",
     "Guid    A pointer to the GUID for the entry to add, update, or remove.\n\
Table   A pointer to the configuration table for the entry to add, update, or remove. May be NULL.",
     "IN EFI_GUID *Guid", "IN VOID *Table", "", "", "", "", "", "", 0},
    {"LoadImage", 0xC8, 0x70, "Loads an EFI image into memory.", 6,
     "EFI_STATUS(EFIAPI * EFI_IMAGE_LOAD) (IN BOOLEAN BootPolicy, IN "
     "EFI_HANDLE ParentImageHandle, IN EFI_DEVICE_PATH_PROTOCOL *DevicePath, "
     "IN VOID *SourceBuffer OPTIONAL, IN UINTN SourceSize, OUT EFI_HANDLE "
     "*ImageHandle)",
     "BootPolicy          If TRUE, indicates that the request originates from the boot manager, and that the boot manager is attempting to load FilePath as a boot selection. Ignored if SourceBuffer is not NULL.\n\
ParentImageHandle   The caller's image handle.\n\
DevicePath          The DeviceHandle specific file path from which the image is loaded.\n\
SourceBuffer        If not NULL, a pointer to the memory location containing a copy of the image to be loaded.\n\
SourceSize          The size in bytes of SourceBuffer. Ignored if SourceBuffer is NULL.\n\
ImageHandle         The pointer to the returned image handle that is created when the image is successfully loaded.",
     "IN BOOLEAN BootPolicy", "IN EFI_HANDLE ParentImageHandle",
     "IN EFI_DEVICE_PATH_PROTOCOL *DevicePath", "IN VOID *SourceBuffer OPTIONAL",
     "IN UINTN SourceSize", "OUT EFI_HANDLE *ImageHandle", "", "", 0},
    {"StartImage", 0xD0, 0x74, "Transfers control to a loaded image's entry point.", 3,
     "EFI_STATUS(EFIAPI * EFI_IMAGE_START) (IN EFI_HANDLE ImageHandle, OUT "
     "UINTN *ExitDataSize, OUT CHAR16 **ExitData OPTIONAL)",
     "ImageHandle    Handle of image to be started.\n\
ExitDataSize   The pointer to the size, in bytes, of ExitData.\n\
ExitData       The pointer to a pointer to a data buffer that includes a Null-terminated string, optionally followed by additional binary data.",
     "IN EFI_HANDLE ImageHandle", "OUT UINTN *ExitDataSize",
     "OUT CHAR16 **ExitData OPTIONAL", "", "", "", "", "", 0},
    {"Exit", 0xD8, 0x78,
     "Terminates a loaded EFI image and returns control to boot services.", 4,
     "EFI_STATUS(EFIAPI * EFI_EXIT) (IN EFI_HANDLE ImageHandle, IN EFI_STATUS "
     "ExitStatus, IN UINTN ExitDataSize, IN CHAR16 *ExitData OPTIONAL)",
     "ImageHandle    Handle that identifies the image. This parameter is passed to the image on entry.\n\
ExitStatus     The image's exit code.\n\
ExitDataSize   The size, in bytes, of ExitData. Ignored if ExitStatus is EFI_SUCCESS.\n\
ExitData       The pointer to a data buffer that includes a Null-terminated string, optionally followed by additional binary data. The string is a description that the caller may use to further indicate the reason for the image's exit. ExitData is only valid if ExitStatus is something other than EFI_SUCCESS. The ExitData buffer must be allocated by calling AllocatePool().",
     "IN EFI_HANDLE ImageHandle", "IN EFI_STATUS ExitStatus", "IN UINTN ExitDataSize",
     "IN CHAR16 *ExitData OPTIONAL", "", "", "", "", 0},
    {"UnloadImage", 0xE0, 0x7c, "Unloads an image.", 1,
     "EFI_STATUS(EFIAPI * EFI_IMAGE_UNLOAD) (IN EFI_HANDLE ImageHandle)",
     "ImageHandle Handle that identifies the image to be unloaded.",
     "IN EFI_HANDLE ImageHandle", "", "", "", "", "", "", "", 0},
    {"ExitBootServices", 0xE8, 0x80, "Terminates all boot services.", 2,
     "EFI_STATUS(EFIAPI * EFI_EXIT_BOOT_SERVICES) (IN EFI_HANDLE ImageHandle, "
     "IN UINTN MapKey)",
     "ImageHandle   Handle that identifies the exiting image.\n\
MapKey        Key to the latest memory map.",
     "IN EFI_HANDLE ImageHandle", "IN UINTN MapKey", "", "", "", "", "", "", 0},
    {"GetNextMonotonicCount", 0xF0, 0x84,
     "Returns a monotonically increasing count for the platform.", 1,
     "EFI_STATUS(EFIAPI * EFI_GET_NEXT_MONOTONIC_COUNT) (OUT UINT64 *Count)",
     "Count The pointer to returned value.", "OUT UINT64 *Count", "", "", "", "", "", "",
     "", 0},
    {"Stall", 0xF8, 0x88, "Induces a fine-grained stall.", 1,
     "EFI_STATUS(EFIAPI * EFI_STALL) (IN UINTN Microseconds)",
     "Microseconds The number of microseconds to stall execution.",
     "IN UINTN Microseconds", "", "", "", "", "", "", "", 0},
    {"SetWatchdogTimer", 0x100, 0x8c, "Sets the system's watchdog timer.", 4,
     "EFI_STATUS(EFIAPI * EFI_SET_WATCHDOG_TIMER) (IN UINTN Timeout, IN UINT64 "
     "WatchdogCode, IN UINTN DataSize, IN CHAR16 *WatchdogData OPTIONAL)",
     "Timeout        The number of seconds to set the watchdog timer to.\n\
WatchdogCode   The numeric code to log on a watchdog timer timeout event.\n\
DataSize       The size, in bytes, of WatchdogData.\n\
WatchdogData   A data buffer that includes a Null-terminated string, optionally followed by additional binary data.",
     "IN UINTN Timeout", "IN UINT64 WatchdogCode", "IN UINTN DataSize",
     "IN CHAR16 *WatchdogData OPTIONAL", "", "", "", "", 0},
    {"ConnectController", 0x108, 0x90, "Connects one or more drivers to a controller.", 4,
     "EFI_STATUS(EFIAPI * EFI_CONNECT_CONTROLLER) (IN EFI_HANDLE "
     "ControllerHandle, IN EFI_HANDLE *DriverImageHandle, OPTIONAL IN "
     "EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath, OPTIONAL IN BOOLEAN "
     "Recursive)",
     "ControllerHandle      The handle of the controller to which driver(s) are to be connected.\n\
DriverImageHandle     A pointer to an ordered list handles that support the EFI_DRIVER_BINDING_PROTOCOL.\n\
RemainingDevicePath   A pointer to the device path that specifies a child of the controller specified by ControllerHandle.\n\
Recursive             If TRUE, then ConnectController() is called recursively until the entire tree of controllers below the controller specified by ControllerHandle have been created. If FALSE, then the tree of controllers is only expanded one level.",
     "IN EFI_HANDLE ControllerHandle", "IN EFI_HANDLE *DriverImageHandle",
     "OPTIONAL IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath",
     "OPTIONAL IN BOOLEAN Recursive", "", "", "", "", 0},
    {"DisconnectController", 0x110, 0x94,
     "Disconnects one or more drivers from a controller.", 3,
     "EFI_STATUS(EFIAPI * EFI_DISCONNECT_CONTROLLER) (IN EFI_HANDLE "
     "ControllerHandle, IN EFI_HANDLE DriverImageHandle, OPTIONAL IN "
     "EFI_HANDLE ChildHandle OPTIONAL)",
     "ControllerHandle    The handle of the controller from which driver(s) are to be disconnected.\n\
DriverImageHandle   The driver to disconnect from ControllerHandle. If DriverImageHandle is NULL, then all the drivers currently managing ControllerHandle are disconnected from ControllerHandle.\n\
ChildHandle         The handle of the child to destroy. If ChildHandle is NULL, then all the children of ControllerHandle are destroyed before the drivers are disconnected from ControllerHandle.",
     "IN EFI_HANDLE ControllerHandle", "IN EFI_HANDLE DriverImageHandle",
     "OPTIONAL IN EFI_HANDLE ChildHandle OPTIONAL", "", "", "", "", "", 0},
    {"OpenProtocol", 0x118, 0x98,
     "Queries a handle to determine if it supports a specified protocol. If "
     "the protocol is supported by the handle, it opens the protocol on behalf "
     "of the calling agent.",
     6,
     "EFI_STATUS(EFIAPI * EFI_OPEN_PROTOCOL) (IN EFI_HANDLE Handle, IN "
     "EFI_GUID *Protocol, OUT VOID **Interface, OPTIONAL IN EFI_HANDLE "
     "AgentHandle, IN EFI_HANDLE ControllerHandle, IN UINT32 Attributes)",
     "Handle             The handle for the protocol interface that is being opened.\n\
Protocol           The published unique identifier of the protocol.\n\
Interface          Supplies the address where a pointer to the corresponding Protocol Interface is returned.\n\
AgentHandle        The handle of the agent that is opening the protocol interface specified by Protocol and Interface.\n\
ControllerHandle   If the agent that is opening a protocol is a driver that follows the UEFI Driver Model, then this parameter is the controller handle that requires the protocol interface. If the agent does not follow the UEFI Driver Model, then this parameter is optional and may be NULL.\n\
Attributes         The open mode of the protocol interface specified by Handle and Protocol.",
     "IN EFI_HANDLE Handle", "IN EFI_GUID *Protocol", "OUT VOID **Interface",
     "OPTIONAL IN EFI_HANDLE AgentHandle", "IN EFI_HANDLE ControllerHandle",
     "IN UINT32 Attributes", "", "", 0},
    {"CloseProtocol", 0x120, 0x9c,
     "Closes a protocol on a handle that was opened using OpenProtocol().", 4,
     "EFI_STATUS(EFIAPI * EFI_CLOSE_PROTOCOL) (IN EFI_HANDLE Handle, IN "
     "EFI_GUID *Protocol, IN EFI_HANDLE AgentHandle, IN EFI_HANDLE "
     "ControllerHandle)",
     "Handle             The handle for the protocol interface that was previously opened with OpenProtocol(), and is now being closed.\n\
Protocol           The published unique identifier of the protocol.\n\
AgentHandle        The handle of the agent that is closing the protocol interface.\n\
ControllerHandle   If the agent that opened a protocol is a driver that follows the UEFI Driver Model, then this parameter is the controller handle that required the protocol interface.",
     "IN EFI_HANDLE Handle", "IN EFI_GUID *Protocol", "IN EFI_HANDLE AgentHandle",
     "IN EFI_HANDLE ControllerHandle", "", "", "", "", 0},
    {"OpenProtocolInformation", 0x128, 0xa0,
     "Retrieves the list of agents that currently have a protocol interface "
     "opened.",
     4,
     "EFI_STATUS(EFIAPI * EFI_OPEN_PROTOCOL_INFORMATION) (IN EFI_HANDLE "
     "Handle, IN EFI_GUID *Protocol, OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY "
     "**EntryBuffer, OUT UINTN *EntryCount)",
     "Handle        The handle for the protocol interface that is being queried.\n\
Protocol      The published unique identifier of the protocol.\n\
EntryBuffer   A pointer to a buffer of open protocol information in the form of EFI_OPEN_PROTOCOL_INFORMATION_ENTRY structures.\n\
EntryCount    A pointer to the number of entries in EntryBuffer.",
     "IN EFI_HANDLE Handle", "IN EFI_GUID *Protocol",
     "OUT EFI_OPEN_PROTOCOL_INFORMATION_ENTRY **EntryBuffer", "OUT UINTN *EntryCount", "",
     "", "", "", 0},
    {"ProtocolsPerHandle", 0x130, 0xa4,
     "Retrieves the list of protocol interface GUIDs that are installed on a "
     "handle in a buffer allocated from pool.",
     3,
     "EFI_STATUS(EFIAPI * EFI_PROTOCOLS_PER_HANDLE) (IN EFI_HANDLE Handle, OUT "
     "EFI_GUID ***ProtocolBuffer, OUT UINTN *ProtocolBufferCount)",
     "Handle                The handle from which to retrieve the list of protocol interface GUIDs.\n\
ProtocolBuffer        A pointer to the list of protocol interface GUID pointers that are installed on Handle.\n\
ProtocolBufferCount   A pointer to the number of GUID pointers present in ProtocolBuffer.",
     "IN EFI_HANDLE Handle", "OUT EFI_GUID ***ProtocolBuffer",
     "OUT UINTN *ProtocolBufferCount", "", "", "", "", "", 0},
    {"LocateHandleBuffer", 0x138, 0xa8,
     "Returns an array of handles that support the requested protocol in a "
     "buffer allocated from pool.",
     5,
     "EFI_STATUS(EFIAPI * EFI_LOCATE_HANDLE_BUFFER) (IN EFI_LOCATE_SEARCH_TYPE "
     "SearchType, IN EFI_GUID *Protocol, OPTIONAL IN VOID *SearchKey, OPTIONAL "
     "IN OUT UINTN *NoHandles, OUT EFI_HANDLE **Buffer)",
     "SearchType   Specifies which handle(s) are to be returned.\n\
Protocol     Provides the protocol to search by. This parameter is only valid for a SearchType of ByProtocol.\n\
SearchKey    Supplies the search key depending on the SearchType.\n\
NoHandles    The number of handles returned in Buffer.\n\
Buffer       A pointer to the buffer to return the requested array of handles that support Protocol.",
     "IN EFI_LOCATE_SEARCH_TYPE SearchType", "IN EFI_GUID *Protocol",
     "OPTIONAL IN VOID *SearchKey", "OPTIONAL IN OUT UINTN *NoHandles",
     "OUT EFI_HANDLE **Buffer", "", "", "", 0},
    {"LocateProtocol", 0x140, 0xac,
     "Returns the first protocol instance that matches the given protocol.", 3,
     "EFI_STATUS(EFIAPI * EFI_LOCATE_PROTOCOL) (IN EFI_GUID *Protocol, IN VOID "
     "*Registration, OPTIONAL OUT VOID **Interface)",
     "Protocol       Provides the protocol to search for.\n\
Registration   Optional registration key returned from RegisterProtocolNotify().\n\
Interface      On return, a pointer to the first interface that matches Protocol and Registration.",
     "IN EFI_GUID *Protocol", "IN VOID *Registration", "OPTIONAL OUT VOID **Interface",
     "", "", "", "", "", 0},
    {"InstallMultipleProtocolInterfaces", 0x148, 0xb0,
     "Installs one or more protocol interfaces into the boot services "
     "environment.",
     1,
     "EFI_STATUS(EFIAPI * EFI_INSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN OUT "
     "EFI_HANDLE *Handle,...)",
     "Handle   The pointer to a handle to install the new protocol interfaces on, or a pointer to NULL if a new handle is to be allocated.\n\
...      A variable argument list containing pairs of protocol GUIDs and protocol interfaces.",
     "IN OUT EFI_HANDLE *Handle", "", "", "", "", "", "", "", 0},
    {"UninstallMultipleProtocolInterfaces", 0x150, 0xb4,
     "Removes one or more protocol interfaces into the boot services "
     "environment.",
     1,
     "EFI_STATUS(EFIAPI * EFI_UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES) (IN "
     "EFI_HANDLE Handle,...)",
     "Handle   The handle to remove the protocol interfaces from.\n\
...      A variable argument list containing pairs of protocol GUIDs and protocol interfaces.",
     "IN EFI_HANDLE Handle", "", "", "", "", "", "", "", 0},
    {"CalculateCrc32", 0x158, 0xb8,
     "Computes and returns a 32-bit CRC for a data buffer.", 3,
     "EFI_STATUS(EFIAPI * EFI_CALCULATE_CRC32) (IN VOID *Data, IN UINTN "
     "DataSize, OUT UINT32 *Crc32)",
     "Data       A pointer to the buffer on which the 32-bit CRC is to be computed.\n\
DataSize   The number of bytes in the buffer Data.\n\
Crc32      The 32-bit CRC that was computed for the data buffer specified by Data and DataSize.",
     "IN VOID *Data", "IN UINTN DataSize", "OUT UINT32 *Crc32", "", "", "", "", "", 0},
    {"CopyMem", 0x160, 0xbc, "Copies the contents of one buffer to another buffer.", 3,
     "VOID(EFIAPI * EFI_COPY_MEM) (IN VOID *Destination, IN VOID *Source, IN "
     "UINTN Length)",
     "Destination   The pointer to the destination buffer of the memory copy.\n\
Source        The pointer to the source buffer of the memory copy.\n\
Length        Number of bytes to copy from Source to Destination.",
     "IN VOID *Destination", "IN VOID *Source", "IN UINTN Length", "", "", "", "", "", 0},
    {"SetMem", 0x168, 0xc0,
     "The SetMem() function fills a buffer with a specified value.", 3,
     "VOID(EFIAPI * EFI_SET_MEM) (IN VOID *Buffer, IN UINTN Size, IN UINT8 "
     "Value)",
     "Buffer   The pointer to the buffer to fill.\n\
Size     Number of bytes in Buffer to fill.\n\
Value    Value to fill Buffer with.",
     "IN VOID *Buffer", "IN UINTN Size", "IN UINT8 Value", "", "", "", "", "", 0},
    {"CreateEventEx", 0x170, 0xc4, "Creates an event in a group.", 6,
     "EFI_STATUS(EFIAPI * EFI_CREATE_EVENT_EX) (IN UINT32 Type, IN EFI_TPL "
     "NotifyTpl, IN EFI_EVENT_NOTIFY NotifyFunction OPTIONAL, IN CONST VOID "
     "*NotifyContext OPTIONAL, IN CONST EFI_GUID *EventGroup OPTIONAL, OUT "
     "EFI_EVENT *Event)",
     "Type             The type of event to create and its mode and attributes.\n\
NotifyTpl        The task priority level of event notifications,if needed.\n\
NotifyFunction   The pointer to the event's notification function, if any.\n\
NotifyContext    The pointer to the notification function's context; corresponds to parameter Context in the notification function.\n\
EventGroup       The pointer to the unique identifier of the group to which this event belongs. If this is NULL, then the function behaves as if the parameters were passed to CreateEvent.\n\
Event            The pointer to the newly created event if the call succeeds; undefined otherwise.",
     "IN UINT32 Type", "IN EFI_TPL NotifyTpl",
     "IN EFI_EVENT_NOTIFY NotifyFunction OPTIONAL",
     "IN CONST VOID *NotifyContext OPTIONAL", "IN CONST EFI_GUID *EventGroup OPTIONAL",
     "OUT EFI_EVENT *Event", "", "", 0}};

struct services_entry runtime_services_table[] = {
    {"GetTime", 0x18, 0x18,
     "Returns the current time and date information, and the time-keeping "
     "capabilities of the hardware platform.",
     2,
     "EFI_STATUS(EFIAPI * EFI_GET_TIME) (OUT EFI_TIME *Time, OUT "
     "EFI_TIME_CAPABILITIES *Capabilities OPTIONAL)",
     "Time           A pointer to storage to receive a snapshot of the current time.\n\
Capabilities   An optional pointer to a buffer to receive the real time clock device's capabilities.",
     "OUT EFI_TIME *Time", "OUT EFI_TIME_CAPABILITIES *Capabilities OPTIONAL", "", "", "",
     "", "", "", 0},
    {"SetTime", 0x20, 0x1c, "Sets the current local time and date information.", 1,
     "EFI_STATUS(EFIAPI * EFI_SET_TIME) (IN EFI_TIME *Time)",
     "Time A pointer to the current time.", "IN EFI_TIME *Time", "", "", "", "", "", "",
     "", 0},
    {"GetWakeupTime", 0x28, 0x20, "Returns the current wakeup alarm clock setting.", 3,
     "EFI_STATUS(EFIAPI * EFI_GET_WAKEUP_TIME) (OUT BOOLEAN *Enabled, OUT "
     "BOOLEAN *Pending, OUT EFI_TIME *Time)",
     "Enabled   Indicates if the alarm is currently enabled or disabled.\n\
Pending   Indicates if the alarm signal is pending and requires acknowledgement.\n\
Time      The current alarm setting.",
     "OUT BOOLEAN *Enabled", "OUT BOOLEAN *Pending", "OUT EFI_TIME *Time", "", "", "", "",
     "", 0},
    {"SetWakeupTime", 0x30, 0x24, "Sets the system wakeup alarm clock time.", 2,
     "EFI_STATUS(EFIAPI * EFI_SET_WAKEUP_TIME) (IN BOOLEAN Enable, IN EFI_TIME "
     "*Time OPTIONAL)",
     "Enabled   Enable or disable the wakeup alarm.\n\
Time      If Enable is TRUE, the time to set the wakeup alarm for. If Enable is FALSE, then this parameter is optional, and may be NULL.",
     "IN BOOLEAN Enable", "IN EFI_TIME *Time OPTIONAL", "", "", "", "", "", "", 0},
    {"SetVirtualAddressMap", 0x38, 0x28,
     "Changes the runtime addressing mode of EFI firmware from physical to "
     "virtual.",
     4,
     "EFI_STATUS(EFIAPI * EFI_SET_VIRTUAL_ADDRESS_MAP) (IN UINTN "
     "MemoryMapSize, IN UINTN DescriptorSize, IN UINT32 DescriptorVersion, IN "
     "EFI_MEMORY_DESCRIPTOR *VirtualMap)",
     "MemoryMapSize       The size in bytes of VirtualMap.\n\
DescriptorSize      The size in bytes of an entry in the VirtualMap.\n\
DescriptorVersion   The version of the structure entries in VirtualMap.\n\
VirtualMap          An array of memory descriptors which contain new virtual address mapping information for all runtime ranges.",
     "IN UINTN MemoryMapSize", "IN UINTN DescriptorSize", "IN UINT32 DescriptorVersion",
     "IN EFI_MEMORY_DESCRIPTOR *VirtualMap", "", "", "", "", 0},
    {"ConvertPointer", 0x40, 0x2c,
     "Determines the new virtual address that is to be used on subsequent "
     "memory accesses.",
     2,
     "EFI_STATUS(EFIAPI * EFI_CONVERT_POINTER) (IN UINTN DebugDisposition, IN "
     "OUT VOID **Address)",
     "DebugDisposition   Supplies type information for the pointer being converted.\n\
Address            A pointer to a pointer that is to be fixed to be the value needed for the new virtual address mappings being applied.",
     "IN UINTN DebugDisposition", "IN OUT VOID **Address", "", "", "", "", "", "", 0},
    {"GetVariable", 0x48, 0x30, "Returns the value of a variable.", 5,
     "EFI_STATUS(EFIAPI * EFI_GET_VARIABLE) (IN CHAR16 *VariableName, IN "
     "EFI_GUID *VendorGuid, OUT UINT32 *Attributes, OPTIONAL IN OUT UINTN "
     "*DataSize, OUT VOID *Data)",
     "VariableName   A Null-terminated string that is the name of the vendor's variable.\n\
VendorGuid     A unique identifier for the vendor.\n\
Attributes     If not NULL, a pointer to the memory location to return the attributes bitmask for the variable.\n\
DataSize       On input, the size in bytes of the return Data buffer. On output the size of data returned in Data.\n\
Data           The buffer to return the contents of the variable.",
     "IN CHAR16 *VariableName", "IN EFI_GUID *VendorGuid", "OUT UINT32 *Attributes",
     "OPTIONAL IN OUT UINTN *DataSize", "OUT VOID *Data", "", "", "", 0},
    {"GetNextVariableName", 0x50, 0x3c, "Enumerates the current variable names.", 3,
     "EFI_STATUS(EFIAPI * EFI_GET_NEXT_VARIABLE_NAME) (IN OUT UINTN "
     "*VariableNameSize, IN OUT CHAR16 *VariableName, IN OUT EFI_GUID "
     "*VendorGuid)",
     "VariableNameSize   The size of the VariableName buffer.\n\
VariableName       On input, supplies the last VariableName that was returned by GetNextVariableName(). On output, returns the Nullterminated string of the current variable.\n\
VendorGuid         On input, supplies the last VendorGuid that was returned by GetNextVariableName(). On output, returns the VendorGuid of the current variable.",
     "IN OUT UINTN *VariableNameSize", "IN OUT CHAR16 *VariableName",
     "IN OUT EFI_GUID *VendorGuid", "", "", "", "", "", 0},
    {"SetVariable", 0x58, 0x38, "Sets the value of a variable.", 5,
     "EFI_STATUS(EFIAPI * EFI_SET_VARIABLE) (IN CHAR16 *VariableName, IN "
     "EFI_GUID *VendorGuid, IN UINT32 Attributes, IN UINTN DataSize, IN VOID "
     "*Data)",
     "VariableName   A Null-terminated string that is the name of the vendor's variable. Each VariableName is unique for each VendorGuid. VariableName must contain 1 or more characters. If VariableName is an empty string, then EFI_INVALID_PARAMETER is returned.\n\
VendorGuid     A unique identifier for the vendor.\n\
Attributes     Attributes bitmask to set for the variable.\n\
DataSize       The size in bytes of the Data buffer. Unless the EFI_VARIABLE_APPEND_WRITE, EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, or EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute is set, a size of zero causes the variable to be deleted. When the EFI_VARIABLE_APPEND_WRITE attribute is set, \nthen a SetVariable() call with a DataSize of zero will not cause any change to the variable value (the timestamp associated with the variable may be updated however even if no new data value is provided,\n see the description of the EFI_VARIABLE_AUTHENTICATION_2 descriptor below. In this case the DataSize will not be zero since the EFI_VARIABLE_AUTHENTICATION_2 descriptor will be populated).\n\
Data           The contents for the variable.",
     "IN CHAR16 *VariableName", "IN EFI_GUID *VendorGuid", "IN UINT32 Attributes",
     "IN UINTN DataSize", "IN VOID *Data", "", "", "", 0},
    {"GetNextHighMonotonicCount", 0x60, 0x3c,
     "Returns the next high 32 bits of the platform's monotonic counter.", 1,
     "EFI_STATUS(EFIAPI * EFI_GET_NEXT_HIGH_MONO_COUNT) (OUT UINT32 "
     "*HighCount)",
     "HighCount The pointer to returned value.", "OUT UINT32 *HighCount", "", "", "", "",
     "", "", "", 0},
    {"ResetSystem", 0x68, 0x40, "Resets the entire platform.", 4,
     "VOID(EFIAPI * EFI_RESET_SYSTEM) (IN EFI_RESET_TYPE ResetType, IN "
     "EFI_STATUS ResetStatus, IN UINTN DataSize, IN VOID *ResetData OPTIONAL)",
     "ResetType     The type of reset to perform.\n\
ResetStatus   The status code for the reset.\n\
DataSize      The size, in bytes, of WatchdogData.\n\
ResetData     For a ResetType of EfiResetCold, EfiResetWarm, or EfiResetShutdown the data buffer starts with a Null-terminated string, optionally followed by additional binary data.",
     "IN EFI_RESET_TYPE ResetType", "IN EFI_STATUS ResetStatus", "IN UINTN DataSize",
     "IN VOID *ResetData OPTIONAL", "", "", "", "", 0},
    {"UpdateCapsule", 0x70, 0x44,
     "Passes capsules to the firmware with both virtual and physical mapping. "
     "Depending on the intended consumption, the firmware may process the "
     "capsule immediately. If the payload should persist across a system "
     "reset, the reset value returned from EFI_QueryCapsuleCapabilities must "
     "be passed into ResetSystem() and will cause the capsule to be processed "
     "by the firmware as part of the reset process.",
     3,
     "EFI_STATUS(EFIAPI * EFI_UPDATE_CAPSULE) (IN EFI_CAPSULE_HEADER "
     "**CapsuleHeaderArray, IN UINTN CapsuleCount, IN EFI_PHYSICAL_ADDRESS "
     "ScatterGatherList OPTIONAL)",
     "CapsuleHeaderArray   Virtual pointer to an array of virtual pointers to the capsules being passed into update capsule.\n\
CapsuleCount         Number of pointers to EFI_CAPSULE_HEADER in CaspuleHeaderArray.\n\
ScatterGatherList    Physical pointer to a set of EFI_CAPSULE_BLOCK_DESCRIPTOR that describes the location in physical memory of a set of capsules.",
     "IN EFI_CAPSULE_HEADER **CapsuleHeaderArray", "IN UINTN CapsuleCount",
     "IN EFI_PHYSICAL_ADDRESS ScatterGatherList OPTIONAL", "", "", "", "", "", 0},
    {"QueryCapsuleCapabilities", 0x78, 0x48,
     "Returns if the capsule can be supported via UpdateCapsule().", 4,
     "EFI_STATUS(EFIAPI * EFI_QUERY_CAPSULE_CAPABILITIES) (IN "
     "EFI_CAPSULE_HEADER **CapsuleHeaderArray, IN UINTN CapsuleCount, OUT "
     "UINT64 *MaximumCapsuleSize, OUT EFI_RESET_TYPE *ResetType)",
     "CapsuleHeaderArray   Virtual pointer to an array of virtual pointers to the capsules being passed into update capsule.\n\
CapsuleCount         Number of pointers to EFI_CAPSULE_HEADER in CaspuleHeaderArray.\n\
MaxiumCapsuleSize    On output the maximum size that UpdateCapsule() can support as an argument to UpdateCapsule() via CapsuleHeaderArray and ScatterGatherList.\n\
ResetType            Returns the type of reset required for the capsule update.",
     "IN EFI_CAPSULE_HEADER **CapsuleHeaderArray", "IN UINTN CapsuleCount",
     "OUT UINT64 *MaximumCapsuleSize", "OUT EFI_RESET_TYPE *ResetType", "", "", "", "",
     0},
    {"QueryVariableInfo", 0x80, 0x4c, "Returns information about the EFI variables.", 4,
     "EFI_STATUS(EFIAPI * EFI_QUERY_VARIABLE_INFO) (IN UINT32 Attributes, OUT "
     "UINT64 *MaximumVariableStorageSize, OUT UINT64 "
     "*RemainingVariableStorageSize, OUT UINT64 *MaximumVariableSize)",
     "Attributes                     Attributes bitmask to specify the type of variables on which to return information.\n\
MaximumVariableStorageSize     On output the maximum size of the storage space available for the EFI variables associated with the attributes specified.\n\
RemainingVariableStorageSize   Returns the remaining size of the storage space available for the EFI variables associated with the attributes specified.\n\
MaximumVariableSize            Returns the maximum size of the individual EFI variables associated with the attributes specified.",
     "IN UINT32 Attributes", "OUT UINT64 *MaximumVariableStorageSize",
     "OUT UINT64 *RemainingVariableStorageSize", "OUT UINT64 *MaximumVariableSize", "",
     "", "", "", 0}};
