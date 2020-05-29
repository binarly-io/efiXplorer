#!/usr/bin/env python3.7

import glob
import hashlib
import json
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
def get_images(firmware_path):
    """Extract efi images from UEFI firmware."""
    if not os.path.isfile(firmware_path):
        print('{} check firmware path'.format(ERROR))
        return False
    fw_data = os.path.join(tempfile.gettempdir(), 'fw_data')
    fw_images = os.path.join(tempfile.gettempdir(), 'fw_images')
    clear(fw_data)
    clear(fw_images)
    utils.get_fw_volume(firmware_path)
    get_efi_images(firmware_path, fw_data, fw_images)
    print('{} check {} directory'.format(DONE, fw_images))


@click.command()
@click.argument('firmware_path')
def get_swsmi_images(firmware_path):
    """Find modules with swsmi handlers."""
    if not os.path.isfile(firmware_path):
        print('{} check firmware path'.format(ERROR))
        return False
    fw_data = os.path.join(tempfile.gettempdir(), 'fw_data')
    fw_images = os.path.join(tempfile.gettempdir(), 'fw_images')
    clear(fw_data)
    clear(fw_images)
    utils.get_fw_volume(firmware_path)
    get_efi_images(firmware_path, fw_data, fw_images)
    fw_swsmi_images = utils.get_swsmi_h_images(fw_images)
    print('{} images with swsmi handlers: {}'.format(
        DONE, json.dumps(fw_swsmi_images, indent=4)))


@click.command()
@click.argument('image_path')
def analyze_image(image_path):
    """Analyze UEFI module with IDA in batch mode."""
    if not os.path.isfile(image_path):
        print('{} check image path'.format(ERROR))
        return False
    script_path = os.path.join('idc', 'efixplorer_start.idc')
    ida_exe = 'idat64'
    machine_type = utils.get_machine_type(image_path)
    if machine_type == utils.IMAGE_FILE_MACHINE_I386:
        ida_exe = 'idat'
    process = subprocess.Popen(
        [ida_exe, '-A', '-S{}'.format(script_path), image_path],
        stdout=subprocess.PIPE)
    # ignore stdout, stderr
    _, _ = process.communicate()
    if os.path.isfile('{}.idb'.format(image_path)) or os.path.isfile(
            '{}.i64'.format(image_path)):
        print('{} check {}.json file'.format(DONE, image_path))
        return True
    print('{} failed to analyze this image'.format(ERROR))
    return False


@click.command()
@click.argument('firmware_path')
@click.option('-w',
              '--workers',
              help='Number of workers (8 by default).',
              type=int)
@click.option('--swsmi',
              help='Analyze images with swsmi handlers only',
              count=True)
def analyze_fw(firmware_path, workers, swsmi):
    """Analyze UEFI firmware with IDA in batch mode."""
    if not os.path.isfile(firmware_path):
        print('{} check firmware path'.format(ERROR))
        return False
    script_path = os.path.join('idc', 'efixplorer_start.idc')
    fw_data = os.path.join(tempfile.gettempdir(), 'fw_data')
    fw_images = os.path.join(tempfile.gettempdir(), 'fw_images')
    with open(firmware_path, 'rb') as f:
        data = f.read()
    fw_md5 = hashlib.md5(data).hexdigest()
    fw_logs = os.path.join(tempfile.gettempdir(), 'fw_logs_{}'.format(fw_md5))
    clear(fw_data)
    clear(fw_images)
    clear(fw_logs)
    if not os.path.isdir(fw_logs):
        os.mkdir(fw_logs)
    utils.get_fw_volume(firmware_path)
    get_efi_images(firmware_path, fw_data, fw_images)
    if not swsmi:
        files = glob.glob(os.path.join(fw_images, '*'))
    else:
        files = utils.get_swsmi_h_images(fw_images)
    if not workers:
        workers = 8
    analyse_all(files, script_path, workers, 'idat', 'idat64')
    # get logs
    logs = glob.glob(os.path.join(fw_images, '*.json'))
    for log in logs:
        log_fname = log.split(os.sep)[-1]
        shutil.copyfile(log, os.path.join(fw_logs, log_fname))
    print('{} check {} directory'.format(DONE, fw_logs))


cli.add_command(get_images)
cli.add_command(get_swsmi_images)
cli.add_command(analyze_image)
cli.add_command(analyze_fw)

if __name__ == '__main__':
    cli()
