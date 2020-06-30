#!/usr/bin/env python3

import os
import platform
import shutil
import subprocess

import click


@click.command()
@click.option('--copy', 'plugins_path', help='path to IDA plugins directory')
@click.argument('idasdk_dir')
def build(idasdk_dir, plugins_path):
    if not os.path.isdir('build'):
        os.mkdir('build')
    os.chdir('build')
    subprocess.call(['cmake', '..', '-DIdaSdk_ROOT_DIR={}'.format(idasdk_dir)])
    subprocess.call(['cmake', '--build', '.', '--config', 'Release'])
    if plugins_path and os.path.isdir(plugins_path):
        if platform.system() == 'Linux':
            print('[DEBUG] copying builds to {}'.format(plugins_path))
            shutil.copy('efiXplorer.so',
                        os.path.join(plugins_path, 'efiXplorer.so'))
            shutil.copy('efiXplorer64.so',
                        os.path.join(plugins_path, 'efiXplorer64.so'))
        if platform.system() == 'Windows':
            print('[DEBUG] copying builds to {}'.format(plugins_path))
            shutil.copy(os.path.join('Release', 'efiXplorer.dll'),
                        os.path.join(plugins_path, 'efiXplorer.dll'))
            shutil.copy(os.path.join('Release', 'efiXplorer64.dll'),
                        os.path.join(plugins_path, 'efiXplorer64.dll'))


# pylint: disable=no-value-for-parameter
if __name__ == '__main__':
    build()
