#!/usr/bin/env python3

import os
import platform
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, as_completed

import click
from elftools.elf.elffile import ELFFile
from tqdm import tqdm

# configuration data
ANALYSER_PATH = os.path.join('idc', 'ida2pat.py')
IDA_PATH = 'idat'
IDA64_PATH = 'idat64'


def get_machine_arch(module_path):
    with open(module_path, 'rb') as f:
        elffile = ELFFile(f)
        if not elffile.has_dwarf_info():
            return None
    return elffile.get_machine_arch()


def analyse_module(module_path, scr_path, idat, idat64):
    _, ext = os.path.splitext(module_path)
    if ext != '.debug':
        return False
    arch = get_machine_arch(module_path)
    if arch == 'x86':
        idat_path = idat
    elif arch == 'x64':
        idat_path = idat64
    else:
        return False
    process = subprocess.Popen(
        [idat_path, '-A', '-S{}'.format(scr_path), module_path],
        stdout=subprocess.PIPE)
    # ignore stdout, stderr
    _, _ = process.communicate()
    # analyse module in batch mode
    os.system(cmd)
    if not (os.path.isfile('{}.i64'.format(module_path))
            or os.path.isfile('{}.idb'.format(module_path))):
        print('[ERROR] module: {}'.format(module_path))
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
        for _ in tqdm(as_completed(futures), **params):
            pass


class dbgs_analyser:
    def __init__(self, dirname, workers):
        self.files = []
        self.root_dir = dirname

    def _get_files(self, dirname):
        items = os.listdir(dirname)
        for item in items:
            new_item = os.path.join(dirname, item)
            if os.path.isfile(new_item):
                self.files.append(new_item)
            if os.path.isdir(new_item):
                self._get_files(new_item)

    @classmethod
    def do(cls, dirname, workers):
        cls = cls(dirname, workers)
        cls._get_files(cls.root_dir)
        analyse_all(cls.files, ANALYSER_PATH, workers, IDA_PATH, IDA64_PATH)


@click.group()
def cli():
    pass


@click.command()
@click.argument('modules_dir')
@click.option('-w',
              '--workers',
              help='Number of workers (8 by default).',
              type=int)
def analyze(modules_dir, workers):
    """Handle modules in specific directory"""
    if not os.path.isdir(modules_dir):
        print('[ERROR] check modules directory')
        return False
    if not workers:
        workers = 8
    start_time = time.time()
    dbgs_analyser.do(modules_dir, workers)
    print('[time] {} s.'.format(round(time.time() - start_time, 3)))
    return True


@click.command()
@click.argument('modules_dir')
def get_sig(modules_dir):
    """Get PAT and SIG file"""
    if not os.path.isdir(modules_dir):
        print('[ERROR] check modules directory')
        return False
    d_an = dbgs_analyser(modules_dir, 1)
    d_an._get_files(modules_dir)
    # get PAT files only
    pat_files = []
    for file in d_an.files:
        _, ext = os.path.splitext(file)
        if ext == '.pat':
            pat_files.append(file)
    result_pat = 'efixplorer.pat'
    result_sig = 'efixplorer.sig'
    result_exc = 'efixplorer.exc'
    pat = open(result_pat, 'ab')
    for pat_file in pat_files:
        with open(pat_file, 'rb') as f:
            data = f.read()
        pat.write(data)
    pat.close()
    if platform.system() == 'Linux':
        os.system(' '.join(['dos2unix', result_pat]))
    os.system(' '.join(['sigmake', result_pat, result_sig]))
    if os.path.isfile(result_exc):
        with open(result_exc, 'r') as f:
            exc_buf = f.read()
        next_line_index = exc_buf.find(os.linesep) + len(os.linesep)
        with open(result_exc, 'w') as f:
            f.write(exc_buf[next_line_index:])
        os.system(' '.join(['sigmake', result_pat, result_sig]))


cli.add_command(analyze)
cli.add_command(get_sig)

if __name__ == '__main__':
    cli()
