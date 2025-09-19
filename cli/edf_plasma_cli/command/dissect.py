"""dissect command implementation"""

from pathlib import Path
from platform import node

from edf_plasma_core.helper.csv import write_csv_gz
from edf_plasma_core.helper.filtering import Filter
from edf_plasma_core.helper.json import write_jsonl_gz
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    DissectorList,
    get_dissectors,
)

from .abc import FileFormat, display_table

_LOGGER = get_logger('cli.command.dissect')
_HOSTNAME_REPL_PATTERN = regexp(r'[^\w]+')
_OUTPUT_FORMAT_STRATEGY = {
    FileFormat.CSV: ('.csv.gz', write_csv_gz),
    FileFormat.JSONL: (
        '.jsonl.gz',
        lambda filepath, _, records: write_jsonl_gz(filepath, records),
    ),
}
_GETATTR_STRATEGY = {
    'slug': lambda dissector: {dissector.slug},
    'tags': lambda dissector: {tag.value for tag in dissector.tags},
}


def _select(filter_spec: str, dissectors: DissectorList) -> DissectorList:
    attribute, values = filter_spec.split(':', 1)
    filter_ = Filter(include=set(values.split(',')))
    getattr_ = _GETATTR_STRATEGY[attribute]
    return [
        dissector
        for dissector in dissectors
        if filter_.accept(getattr_(dissector))
    ]


def _run_dissector(
    dissector: Dissector,
    target: Path,
    hostname: str,
    file_format: FileFormat,
    prefix: bool,
    output_directory: Path,
) -> tuple[Path, Path]:
    targets = [target]
    if target.is_dir():
        targets = list(dissector.select(target))
    hostname = _HOSTNAME_REPL_PATTERN.sub('_', hostname).upper()
    ctx_list = [
        DissectionContext(
            dissector=dissector.slug,
            hostname=hostname,
            source=str(target),
            filepath=target,
        )
        for target in targets
    ]
    prefix = f'{hostname}_' if prefix else ''
    output_directory.mkdir(parents=True, exist_ok=True)
    extension, write_records_to_file = _OUTPUT_FORMAT_STRATEGY[file_format]
    out_filepath = output_directory / f'{prefix}{dissector.slug}{extension}'
    err_filepath = (
        output_directory / f'{prefix}{dissector.slug}_error{extension}'
    )
    write_records_to_file(
        out_filepath,
        dissector.table_schema.names,
        dissector.dissect_many(ctx_list),
    )
    write_records_to_file(
        err_filepath,
        dissector.error_table_schema.names,
        dissector.process_errors(ctx_list),
    )
    return out_filepath, err_filepath


def _dissect_cmd(args):
    rows = []
    dissectors = get_dissectors()
    if args.filter:
        try:
            dissectors = _select(args.filter, dissectors)
        except KeyError:
            _LOGGER.error(
                "invalid filter attribute, available attributes are %s",
                list(_GETATTR_STRATEGY.keys()),
            )
            return
    for dissector in dissectors:
        file_format = FileFormat(args.file_format)
        out_filepath, err_filepath = _run_dissector(
            dissector,
            args.target,
            args.hostname,
            file_format,
            args.prefix,
            args.output_directory,
        )
        rows.append(
            [
                dissector.slug,
                str(out_filepath.resolve()),
                str(err_filepath.resolve()),
            ]
        )
    display_table(
        args.format,
        [
            'dissector',
            {'header': 'out_filepath', 'overflow': 'fold'},
            {'header': 'err_filepath', 'overflow': 'fold'},
        ],
        rows,
        show_header=False,
    )


def setup_command(cmd):
    """Setup init command parser"""
    dissect = cmd.add_parser('dissect', help="Run a single dissector")
    dissect.add_argument(
        '--file-format',
        '--ff',
        choices=[fmt.value for fmt in FileFormat],
        default=FileFormat.CSV.value,
        help="Output file format",
    )
    dissect.add_argument(
        '--prefix',
        action='store_true',
        help="Prefix output file with hostname",
    )
    dissect.add_argument(
        '--hostname', default=node(), help="Hostname for given artifact"
    )
    dissect.add_argument(
        '--filter',
        help="Dissector filter, e.g. 'tags:ios' or 'slug:microsoft_lnk,microsoft_mft'",
    )
    dissect.add_argument(
        'target', type=Path, help="Filepath or directory to dissect"
    )
    dissect.add_argument(
        'output_directory', type=Path, help="Dissector output directory"
    )
    dissect.set_defaults(func=_dissect_cmd)
