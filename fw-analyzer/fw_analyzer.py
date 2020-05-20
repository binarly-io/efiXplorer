#!/usr/bin/env python3.7

import glob
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed

import click
from tools import utils
from tools.get_efi_images import get_efi_images
from tqdm import tqdm

DONE = click.style('DONE', fg='green')
ERROR = click.style('ERROR', fg='red')


def analyse_module(module_path, scr_path, idat, idat64):
    machine_type = utils.get_machine_type(module_path)
    ida_exe = idat64
    if machine_type == utils.IMAGE_FILE_MACHINE_I386:
        ida_exe = idat
    cmd = ' '.join([ida_exe, '-c -A -S{}'.format(scr_path), module_path])
    # analyse module in batch mode
    process = subprocess.Popen(
        [idat64, '-A', '-S{}'.format(scr_path), module_path],
        stdout=subprocess.PIPE)
    # ignore stdout, stderr
    _, _ = process.communicate()
    if not (os.path.isfile('{}.i64'.format(module_path))
            or os.path.isfile('{}.idb'.format(module_path))):
        print('{res} module: {module}'.format(res=ERROR, module=module_path))
        exit()
    return True


def analyse_all(files, scr_path, max_workers, idat, idat64):
    # check first module
    analyse_module(files[0], scr_path, idat, idat64)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(analyse_module, module, scr_path, idat, idat64)
            for module in files[1:]
        ]
        params = {
            'total': len(futures),
            'unit': 'module',
            'unit_scale': True,
            'leave': True
        }
        for f in tqdm(as_completed(futures), **params):
            pass


def clear(dirname):
    for root, dirs, files in os.walk(dirname, topdown=False):
        for name in files:
            os.remove(os.path.join(root, name))
        for name in dirs:
            os.rmdir(os.path.join(root, name))


@click.group()
def cli():
    pass


@click.command()
@click.argument('firmware_path')
@click.option('-w',
              '--workers',
              help='Number of workers (8 by default).',
              type=int)
@click.option('--idat', help='Path to idat executable.')
@click.option('--idat64', help='Path to idat64 executable.')
def analyze_fw(firmware_path, idat, idat64, workers):
    """Analyze UEFI firmware with IDA in batch mode."""
    if not os.path.isfile(firmware_path):
        print('{} check firmware path'.format(ERROR))
        return False
    dir_name = os.path.join(tempfile.gettempdir(), 'all')
    pe_dir = os.path.join(tempfile.gettempdir(), 'modules')
    logs_dir = os.path.join(tempfile.gettempdir(), 'logs')
    clear(dir_name)
    clear(pe_dir)
    clear(logs_dir)
    if not os.path.isdir(logs_dir):
        os.mkdir(logs_dir)
    get_efi_images(firmware_path, dir_name, pe_dir)
    if not os.path.isfile(idat64):
        print('{} check idat64 path'.format(ERROR))
        return False
    ida_dir = os.path.dirname(idat64)
    ida_idc = os.path.join(ida_dir, 'idc')
    if not os.path.isdir(ida_idc):
        print('{} check idat64 path'.format(ERROR))
        return False
    if not os.path.isfile(idat):
        print('{} check idat path'.format(ERROR))
        return False
    script_path = os.path.join(ida_idc, 'efixplorer_start.idc')
    shutil.copy('efixplorer_start.idc', script_path)
    files = glob.glob(os.path.join(pe_dir, '*'))
    if not workers:
        workers = 8
    analyse_all(files, script_path, workers, idat, idat64)
    # get logs
    logs = glob.glob(os.path.join(pe_dir, '*.json'))
    for log in logs:
        log_fname = log.split(os.sep)[-1]
        shutil.copyfile(log, os.path.join(logs_dir, log_fname))
    print('{} check {} directory'.format(DONE, logs_dir))


@click.command()
@click.argument('image_path')
@click.option('--idat64', help='Path to idat64 executable.')
def analyze_image(image_path, idat64):
    """Analyze UEFI module with IDA in batch mode. The analysis result is saved to .json file."""
    if not os.path.isfile(image_path):
        print('{} check image path'.format(ERROR))
        return False
    if not os.path.isfile(idat64):
        print('{} check idat64 path'.format(ERROR))
        return False
    ida_dir = os.path.dirname(idat64)
    ida_idc = os.path.join(ida_dir, 'idc')
    if not os.path.isdir(ida_idc):
        print('{} check idat64 path'.format(ERROR))
        return False
    script_path = os.path.join(ida_idc, 'efixplorer_start.idc')
    shutil.copy('efixplorer_start.idc', script_path)
    process = subprocess.Popen(
        [idat64, '-A', '-S{}'.format(script_path), image_path],
        stdout=subprocess.PIPE)
    # ignore stdout, stderr
    _, _ = process.communicate()
    print('{} check {}.json file'.format(DONE, image_path))


cli.add_command(analyze_image)
cli.add_command(analyze_fw)

if __name__ == '__main__':
    cli()
