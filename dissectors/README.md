# EDF Plasma Dissectors

## Introduction

This package implements Plasma Framework's built-in dissectors.

<br>

## Setup

```bash
# first, install edf-plasma-dissectors dependencies
apt install autoconf \
            automake \
            autopoint \
            build-essential \
            git \
            libsystemd-dev \
            libtool \
            pkg-config \
            python3-dev \
            python3-venv
# create a virtual environment
python3 -m venv venv
# install edf-plasma-cli (will also install edf-plasma-core and edf-plasma-dissectors)
venv/bin/python -m pip install edf-plasma-dissectors[pcap,linux,binary,memdump,windows]
# then you can use it to create your own dissectors
```

<br>

## Creating a Custom Dissector

Suppose we want to create a dissector extract and normalize data from auditd log files


```python
"""Auditd Dissector"""
# ------------------------------------------------------------------------------
# import python libraries
# ------------------------------------------------------------------------------
from pathlib import Path
# ------------------------------------------------------------------------------
# import concepts and helpers from edf-plasma-core
# ------------------------------------------------------------------------------
from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.datetime import from_unix_timestamp, to_iso_fmt
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.streaming import (
    lines_from_filepath,
    lines_from_gz_filepath,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator
# ------------------------------------------------------------------------------
# initialize private globals (logger and constant values)
# ------------------------------------------------------------------------------
_LOGGER = get_logger('dissectors.linux.auditd')
_GLOB_PATTERN = 'audit.log*'
_PATTERN = regexp(
    r'type=(?P<type>[^\s]+) [^\(]+\((?P<date>[^\:]+):(?P<id>[^\)]+)\): (?P<data>.+)'
)
# ------------------------------------------------------------------------------
# implement the dissector selection routine
#
# the root directory storing artifacts is passed to the selection routine which
# usually walks through it recursively yielding path for files it can dissect.
# ------------------------------------------------------------------------------
def _select_impl(directory: Path) -> PathIterator:
    for filepath in directory.rglob(_GLOB_PATTERN):
        if not filepath.is_file():
            continue
        yield filepath
# ------------------------------------------------------------------------------
# implement the dissector dissection routine
#
# each selected file is passed to the dissection routine using a dissection
# context. Artifact analysis produces records yielded by the dissection routine.
# ------------------------------------------------------------------------------
def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    skipped = 0
    lines_from_filepath_strategy = (
        lines_from_gz_filepath
        if ctx.filepath.suffix == '.gz'
        else lines_from_filepath
    )
    for line in lines_from_filepath_strategy(ctx.filepath):
        line = line.rstrip()
        match = _PATTERN.search(line)
        if not match:
            skipped += 1
            continue
        auditd_date = float(match.group('date'))
        auditd_date = from_unix_timestamp(auditd_date * 1000 * 1000)
        yield {
            'auditd_type': match.group('type'),
            'auditd_date': to_iso_fmt(auditd_date),
            'auditd_id': match.group('id'),
            'auditd_data': match.group('data'),
        }
    if skipped:
        _LOGGER.warning("skipped %s lines.", skipped)
# ------------------------------------------------------------------------------
# instanciate the dissector and define properties
# ------------------------------------------------------------------------------
DISSECTOR = Dissector(
    slug='linux_auditd',
    tags={Tag.LINUX},
    columns=[
        Column('auditd_type', DataType.STR),
        Column('auditd_date', DataType.STR),
        Column('auditd_id', DataType.INT),
        Column('auditd_data', DataType.STR),
    ],
    description="auditd log",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
# ------------------------------------------------------------------------------
# dynamically register the dissector
# ------------------------------------------------------------------------------
register_dissector(DISSECTOR)
```

<br>

## License

Distributed under the [MIT License](LICENSE).

<br>

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](https://github.com/CERT-EDF/plasma/blob/main/CONTRIBUTING.md).

## Past contributors (before open sourcing)

- [koromodako](https://github.com/koromodako)
- [SPToast](https://github.com/SPToast)
- [alex532h](https://github.com/alex532h)

<br>

## Security

To report a (suspected) security issue, see [SECURITY.md](https://github.com/CERT-EDF/plasma/blob/main/SECURITY.md).
