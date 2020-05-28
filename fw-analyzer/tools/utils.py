import glob
import os

# PE constants
PE_OFFSET = 0x3c
IMAGE_FILE_MACHINE_IA64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014c

# GUIDS
EFI_SMM_SW_DISPATCH_PROTOCOL_GUID = b'\x73\xb7\x41\xe5\x11\xdd\x0c\x42\xb0\x26\xdf\x99\x36\x53\xf8\xbf'
EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID = b'\xdc\xc6\xa3\x18\xea\x5e\xc8\x48\xa1\xc1\xb5\x33\x89\xf9\x89\x99'


def get_num_le(bytearr):
    """get le-number from data"""
    num_le = 0
    for i in range(len(bytearr)):
        num_le += bytearr[i] * pow(256, i)
    return num_le


def get_machine_type(module_path):
    """get architecture"""
    with open(module_path, 'rb') as module:
        data = module.read()
    PE_POINTER = get_num_le(data[PE_OFFSET:PE_OFFSET + 1:])
    FH_POINTER = PE_POINTER + 4
    machine_type = data[FH_POINTER:FH_POINTER + 2:]
    type_value = get_num_le(machine_type)
    return type_value


def get_fw_volume(fw_path):
    """get "firmware volume" data from entire firmware"""
    with open(fw_path, 'rb') as f:
        fw_data = f.read()
    sig_index = fw_data.find(b'_FVH')
    if sig_index < 40:
        return False
    with open(fw_path, 'wb') as f:
        f.write(fw_data[sig_index - 40:])
    return True


def get_swsmi_h_images(fw_images):
    """get images with swsmi handlers"""
    files = glob.glob(os.path.join(fw_images, '*'))
    fw_swsmi_images = []
    for file in files:
        with open(file, 'rb') as f:
            data = f.read()
        if (EFI_SMM_SW_DISPATCH_PROTOCOL_GUID in data) or (
                EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID in data):
            fw_swsmi_images.append(file)
    return fw_swsmi_images
