import glob
import json
import os
import shutil
import zipfile

import click


@click.group()
def cli():
    pass


@click.command()
@click.argument('directory')
def extract_all(directory):
    zip_files = glob.glob(os.path.join(directory, '*'))
    for zip_file in zip_files:
        zfile = zipfile.ZipFile(zip_file)
        for fname in zfile.namelist():
            if not fname.split('.')[-1].lower() in [
                    'exe', 'bat', 'ini', 'txt'
            ]:
                zfile.extract(fname, os.path.join('gb_dump'))


@click.command()
@click.argument('directory')
def get_new(directory):
    files = glob.glob(os.path.join(directory, '*'))
    info = {}
    for file in files:
        root, version = os.path.splitext(file)
        prefix = root.split(os.sep)[-1]
        if not prefix in info:
            info[prefix] = []
        info[prefix].append(version)
    print('[INFO] {}'.format(json.dumps(info, indent=4)))
    gb_new = []
    for prefix in info:
        gb_new.append(
            os.path.join(directory, '{}{}'.format(prefix, info[prefix][-1])))
    if not os.path.isdir('gb_new'):
        os.mkdir('gb_new')
    for new in gb_new:
        shutil.copy(new, os.path.join('gb_new', new.split(os.sep)[-1]))


cli.add_command(extract_all)
cli.add_command(get_new)

if __name__ == '__main__':
    cli()
