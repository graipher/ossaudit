# Copyright (c) 2019, Hans Jerry Illikainen <hji@dyntopia.com>
#
# SPDX-License-Identifier: BSD-2-Clause

import shutil
import sys
from typing import IO, List, Tuple

import click
import texttable

from . import audit, cache, option, packages


def validate_threshold(threshold: float):
    if 0 <= threshold <= 10 or threshold == -1:
        return threshold
    raise click.BadParameter("CVSS score can only be from 0 to 10")

@click.command()
@option.add_config(
    "--config",
    "-c",
    help="Configuration file.",
)
@option.add(
    "--installed",
    "-i",
    is_flag=True,
    help="Audit installed packages.",
)
@option.add(
    "--file",
    "-f",
    "files",
    multiple=True,
    type=click.File(),
    help="Audit packages in file (can be specified multiple times).",
)
@option.add(
    "--username",
    help="Username for authentication.",
)
@option.add(
    "--token",
    help="Token for authentication.",
)
@option.add(
    "--column",
    "columns",
    default=["name", "version", "title"],
    multiple=True,
    show_default=True,
    help="Column to show (can be specified multiple times).",
)
@option.add(
    "--ignore-id",
    "ignore_ids",
    multiple=True,
    help=(
        "Ignore a vulnerability by Sonatype ID or CVE "
        "(can be specified multiple times)."
    ),
)
@option.add(
    "--ignore-cache",
    is_flag=True,
    help="Temporarily ignore existing cache.",
)
@option.add(
    "--reset-cache",
    is_flag=True,
    help="Remove existing cache.",
)
@option.add(
    "--threshold",
    type=int,
    default=-1,
    callback=validate_threshold,
    help="Failure threshold.",
)
def cli(
        installed: bool,
        files: List[IO[str]],
        username: str,
        token: str,
        columns: Tuple[str],
        ignore_ids: Tuple[str],
        ignore_cache: bool,
        reset_cache: bool,
        threshold: float
) -> None:
    if reset_cache:
        cache.reset()

    pkgs = []  # type: list
    if installed:
        pkgs += packages.get_installed()
    if files:
        pkgs += packages.get_from_files(files)

    try:
        vulns = [
            v for v in audit.components(pkgs, username, token, ignore_cache)
            if v.id not in ignore_ids and v.cve not in ignore_ids
        ]
    except audit.AuditError as e:
        raise click.ClickException(str(e))

    if vulns:
        size = shutil.get_terminal_size()
        table = texttable.Texttable(max_width=size.columns)
        table.header(columns)
        table.set_cols_dtype(["t" for _ in range(len(columns))])
        table.add_rows([[getattr(v, c.lower(), "")
                         for c in columns]
                        for v in vulns], False)
        click.echo(table.draw())

    vlen, plen = len(vulns), len(pkgs)
    if threshold >= 0:
        tlen = len([v for v in vulns if int(v.cvss_score) >= threshold])
        click.echo("Found {} vulnerabilities in {} packages, {} above {}".format(vlen, plen, tlen, threshold))
        sys.exit(tlen != 0)
    else:
        click.echo("Found {} vulnerabilities in {} packages".format(vlen, plen))
        sys.exit(vlen != 0)
