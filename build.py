#!/usr/bin/env python3

import os

import click


@click.command()
@click.argument('idasdk_dir')
def build(idasdk_dir):
    if not os.path.isdir('build'):
        os.mkdir('build')
    os.chdir('build')
    os.system('cmake .. -DIdaSdk_ROOT_DIR={}'.format(idasdk_dir))
    os.system('cmake --build . --config Release')


# pylint: disable=no-value-for-parameter
if __name__ == '__main__':
    build()
