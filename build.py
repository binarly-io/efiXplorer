#!/usr/bin/env python3

import os
import pathlib
import platform
import shutil
import subprocess

import click


def search_so(d):
    return list(pathlib.Path(d).rglob("*.so"))


def search_dll(d):
    return list(pathlib.Path(d).rglob("*.dll"))


def search_dylib(d):
    return list(pathlib.Path(d).rglob("*.dylib"))


@click.group()
def cli():
    pass


@click.command()
@click.option("--copy", "plugins_path", help="path to IDA plugins directory")
@click.option(
    "--batch",
    "batch",
    type=bool,
    default=False,
    help="set to True if the plugin will be used in batch mode",
)
@click.argument("idasdk_dir")
def build_plugin(idasdk_dir, plugins_path, batch):
    if not os.path.isdir("build"):
        os.mkdir("build")
    os.chdir("build")
    if batch:
        subprocess.call(
            [
                "cmake",
                "..",
                "-DBATCH=1",
                "-DIdaSdk_ROOT_DIR={}".format(idasdk_dir),
            ]
        )
    else:
        subprocess.call(
            [
                "cmake",
                "..",
                "-DIdaSdk_ROOT_DIR={}".format(idasdk_dir),
            ]
        )
    subprocess.call(["cmake", "--build", ".", "--config", "Release"])
    if plugins_path and os.path.isdir(plugins_path):
        print("[DEBUG] copying builds to {}".format(plugins_path))
        if platform.system() == "Linux":
            for plugin_bin in search_so("."):
                _, fname = os.path.split(plugin_bin)
                shutil.copy(plugin_bin, os.path.join(plugins_path, fname))
        if platform.system() == "Windows":
            for plugin_bin in search_dll("."):
                _, fname = os.path.split(plugin_bin)
                shutil.copy(plugin_bin, os.path.join(plugins_path, fname))
        if platform.system() == "Darwin":
            for plugin_bin in search_dylib("."):
                _, fname = os.path.split(plugin_bin)
                shutil.copy(plugin_bin, os.path.join(plugins_path, fname))


@click.command()
@click.option("--copy", "loaders_path", help="path to IDA loaders directory")
@click.argument("idasdk_dir")
def build_loader(idasdk_dir, loaders_path):
    os.chdir("efiXloader")
    if not os.path.isdir("build"):
        os.mkdir("build")
    os.chdir("build")
    subprocess.call(
        [
            "cmake",
            "..",
            "-DIdaSdk_ROOT_DIR={}".format(idasdk_dir),
        ]
    )
    subprocess.call(["cmake", "--build", ".", "--config", "Release"])
    if loaders_path and os.path.isdir(loaders_path):
        print("[DEBUG] copying builds to {}".format(loaders_path))
        if platform.system() == "Windows":
            for loader_bin in search_dll("."):
                _, fname = os.path.split(loader_bin)
                shutil.copy(loader_bin, os.path.join(loaders_path, fname))


cli.add_command(build_plugin)
cli.add_command(build_loader)


if __name__ == "__main__":
    cli()
