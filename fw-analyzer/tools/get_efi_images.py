################################################################################
# MIT License
#
# Copyright (c) 2018-2020 yeggor
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
################################################################################

import os
import shutil
import sys
from glob import glob

import click
import colorama
import uefi_firmware

from .guid_db import UEFI_GUIDS


def get_files(directory_name, pe_dir):
    """get efi images from "all" directory"""
    if not os.path.isdir(pe_dir):
        os.mkdir(pe_dir)
    bar_template = click.style('%(label)s  %(bar)s | %(info)s', fg='cyan')
    files = os.listdir(directory_name)
    label = 'Obtaining UEFI images'
    with click.progressbar(files,
                           length=len(files),
                           bar_template=bar_template,
                           label=label) as bar:
        for obj in bar:
            src = os.path.join(directory_name, obj)
            template = os.path.join(directory_name, '*.ui')
            if os.path.isfile(src):
                if obj[-3:] == '.pe':
                    if len(glob(template)) == 1:
                        ui_path = glob(template)[0]
                        with open(ui_path, 'rb') as ui:
                            pe_name = ui.read().replace(b'\x00', b'')
                            dst = os.path.join(pe_dir, pe_name.decode('utf-8'))
                    else:
                        # no UI section, try to get a friendly name from the GUID database
                        pe_guid = directory_name.split(os.path.sep)[-2]
                        pe_guid = pe_guid.replace("file-", "").upper()
                        pe_name = UEFI_GUIDS.get(pe_guid)
                        if not pe_name:
                            # unknown GUID
                            pe_name = pe_guid
                        dst = os.path.join(pe_dir, pe_name)
                    shutil.copy(src, dst)
            if os.path.isdir(src):
                get_files(src, pe_dir)
    return True


class Dumper():
    def __init__(self, fw_name, dir_name, pe_dir):
        self.fw_name = fw_name
        self.dir_name = dir_name
        self.pe_dir = pe_dir
        if not os.path.isdir(self.dir_name):
            os.mkdir(self.dir_name)
        if not os.path.isdir(self.pe_dir):
            os.mkdir(self.pe_dir)

    def dump_all(self):
        if not os.path.isfile(self.fw_name):
            print('[-] Check {0} file'.format(self.fw_name))
            return False
        with open(self.fw_name, 'rb') as fw:
            file_content = fw.read()
        parser = uefi_firmware.AutoParser(file_content)
        if parser.type() == 'unknown':
            print('[-] This type of binary is not supported')
            return False
        firmware = parser.parse()
        firmware.dump(self.dir_name)
        return True

    def get_pe_files(self):
        get_files(self.dir_name, self.pe_dir)


def get_efi_images(fw_name, dir_name, pe_dir):
    """get images from firmware"""
    colorama.init()  # for correct color display in uefi_firmware module
    dumper = Dumper(fw_name, dir_name, pe_dir)
    if not dumper.dump_all():
        exit()
    dumper.get_pe_files()
    return True
