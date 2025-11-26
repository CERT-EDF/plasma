"""dissect command implementation"""

from collections.abc import Iterable
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from platform import node
from queue import Queue
from threading import Thread

from edf_plasma_core.dissector import (
    DissectionContext,
    DissectionContextQueue,
    Dissector,
    DissectorList,
    get_dissectors,
)
from edf_plasma_core.helper.csv import write_csv_gz
from edf_plasma_core.helper.filtering import Filter
from edf_plasma_core.helper.json import write_jsonl_gz
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.matching import regexp
from edf_plasma_core.helper.perfmeter import PerformanceMeter
from edf_plasma_core.helper.typing import RecordQueue

from .abc import FileFormat, display_table

_LOGGER = get_logger('cli.command.dissect')
_HOSTNAME_REPL_PATTERN = regexp(r'[^\w]+')
_EXTENSION_STRATEGY = {
    FileFormat.CSV: '.csv.gz',
    FileFormat.JSONL: '.jsonl.gz',
}
_WRITE_FUNC_STRATEGY = {
    FileFormat.CSV: write_csv_gz,
    FileFormat.JSONL: (
        lambda filepath, _, records: write_jsonl_gz(filepath, records)
    ),
}
_GETATTR_STRATEGY = {
    'slug': lambda dissector: {dissector.slug},
    'tags': lambda dissector: {tag.value for tag in dissector.tags},
}


@dataclass(kw_only=True)
class DissectorContext:
    """Dissector Context"""

    target: Path
    hostname: str
    file_format: FileFormat
    prefix: bool
    output_directory: Path
    parallel_surgeons: int

    @cached_property
    def extension(self) -> str:
        """File format extension"""
        return _EXTENSION_STRATEGY[self.file_format]

    @cached_property
    def sanitized_hostname(self) -> str:
        """Hostname"""
        return _HOSTNAME_REPL_PATTERN.sub('_', self.hostname).upper()

    def selected_targets(self, dissector: Dissector) -> Iterable[Path]:
        """Selected targets"""
        if self.target.is_dir():
            return dissector.select(self.target)
        return [self.target]

    def out_filepath(self, dissector: Dissector) -> Path:
        """Output file path"""
        prefix = f'{self.sanitized_hostname}_' if self.prefix else ''
        filename = f'{prefix}{dissector.slug}{self.extension}'
        return self.output_directory / filename

    def err_filepath(self, dissector: Dissector) -> Path:
        """Error file path"""
        prefix = f'{self.sanitized_hostname}_' if self.prefix else ''
        filename = f'{prefix}{dissector.slug}_error{self.extension}'
        return self.output_directory / filename


def _select(filter_spec: str, dissectors: DissectorList) -> DissectorList:
    attribute, values = filter_spec.split(':', 1)
    filter_ = Filter(include=set(values.split(',')))
    getattr_ = _GETATTR_STRATEGY[attribute]
    return [
        dissector
        for dissector in dissectors
        if filter_.accept(getattr_(dissector))
    ]


def _selection_routine(
    processing_queue: Queue,
    dissector_ctx: DissectorContext,
    dissector: Dissector,
    perfmeter: PerformanceMeter,
):
    for target in dissector_ctx.selected_targets(dissector):
        ctx = DissectionContext(
            dissector=dissector.slug,
            hostname=dissector_ctx.hostname,
            source=str(target),
            filepath=target,
        )
        processing_queue.put(ctx)
        perfmeter.tick()
    processing_queue.put(None)


def _dissection_routine(
    record_queue: RecordQueue,
    pre_dissection_queue: DissectionContextQueue,
    post_dissection_queue: DissectionContextQueue,
    dissector: Dissector,
):
    while True:
        ctx = pre_dissection_queue.get()
        if not ctx:
            break
        for record in dissector.dissect(ctx):
            record_queue.put(record)
        post_dissection_queue.put(ctx)


def _consume_records(record_queue: RecordQueue):
    while True:
        record = record_queue.get()
        if not record:
            break
        yield record


def _write_records_routine(
    record_queue: RecordQueue,
    dissector_ctx: DissectorContext,
    dissector: Dissector,
):
    write_records_to_file = _WRITE_FUNC_STRATEGY[dissector_ctx.file_format]
    write_records_to_file(
        dissector_ctx.out_filepath(dissector),
        dissector.table_schema.names,
        _consume_records(record_queue),
    )


def _consume_errors(post_dissection_queue: DissectionContextQueue):
    while True:
        ctx = post_dissection_queue.get()
        if not ctx:
            break
        yield from ctx.errors_as_records()


def _write_errors_routine(
    post_dissection_queue: Queue,
    dissector_ctx: DissectorContext,
    dissector: Dissector,
):
    write_records_to_file = _WRITE_FUNC_STRATEGY[dissector_ctx.file_format]
    write_records_to_file(
        dissector_ctx.err_filepath(dissector),
        dissector.error_table_schema.names,
        _consume_errors(post_dissection_queue),
    )


def _run_dissector(
    dissector: Dissector,
    dissector_ctx: DissectorContext,
    perfmeter: PerformanceMeter,
) -> tuple[Path, Path]:
    record_queue = Queue(maxsize=50)
    pre_dissection_queue = Queue(maxsize=dissector_ctx.parallel_surgeons)
    post_dissection_queue = Queue()
    error_writer_thread = Thread(
        target=_write_errors_routine,
        args=(post_dissection_queue, dissector_ctx, dissector),
    )
    record_writer_thread = Thread(
        target=_write_records_routine,
        args=(record_queue, dissector_ctx, dissector),
    )
    surgeon_threads = [
        Thread(
            target=_dissection_routine,
            args=(
                record_queue,
                pre_dissection_queue,
                post_dissection_queue,
                dissector,
            ),
        )
        for i in range(dissector_ctx.parallel_surgeons)
    ]
    selector_thread = Thread(
        target=_selection_routine,
        args=(
            pre_dissection_queue,
            dissector_ctx,
            dissector,
            perfmeter,
        ),
    )
    error_writer_thread.start()
    record_writer_thread.start()
    for surgeon_thread in surgeon_threads:
        surgeon_thread.start()
    selector_thread.start()
    selector_thread.join()
    for _ in surgeon_threads:
        pre_dissection_queue.put(None)
    for surgeon_thread in surgeon_threads:
        surgeon_thread.join()
    record_queue.put(None)
    record_writer_thread.join()
    post_dissection_queue.put(None)
    error_writer_thread.join()


def _dissector_routine(
    dissector_queue: Queue[Dissector],
    dissector_ctx: DissectorContext,
):
    while True:
        dissector = dissector_queue.get()
        if not dissector:
            break
        perfmeter = PerformanceMeter()
        with perfmeter:
            _run_dissector(dissector, dissector_ctx, perfmeter)
        _LOGGER.info(
            "dissector=%s, files=%s, elapsed=%s",
            dissector.slug,
            perfmeter.count,
            perfmeter.elapsed,
        )


def _dissect_cmd(args):
    dissectors = get_dissectors()
    parallel_surgeons = max(1, args.parallel_surgeons)
    parallel_dissectors = max(1, args.parallel_dissectors)
    if args.filter:
        try:
            dissectors = _select(args.filter, dissectors)
        except KeyError:
            _LOGGER.error(
                "invalid filter attribute, available attributes are %s",
                list(_GETATTR_STRATEGY.keys()),
            )
            return
    args.output_directory.mkdir(parents=True, exist_ok=True)
    dissector_ctx = DissectorContext(
        target=args.target,
        hostname=args.hostname,
        file_format=FileFormat(args.file_format),
        prefix=args.prefix,
        output_directory=args.output_directory,
        parallel_surgeons=parallel_surgeons,
    )
    dissector_queue = Queue(maxsize=parallel_dissectors)
    dissector_threads = [
        Thread(
            target=_dissector_routine,
            args=(dissector_queue, dissector_ctx),
        )
        for i in range(parallel_dissectors)
    ]
    perfmeter = PerformanceMeter()
    with perfmeter:
        for dissector_thread in dissector_threads:
            dissector_thread.start()
        for dissector in dissectors:
            dissector_queue.put(dissector)
        for _ in dissector_threads:
            dissector_queue.put(None)
        for dissector_thread in dissector_threads:
            dissector_thread.join()
    _LOGGER.info(
        "dissectors=%d, elapsed=%s", len(dissectors), perfmeter.elapsed
    )
    display_table(
        args.format,
        [
            'dissector',
            {'header': 'out_filepath', 'overflow': 'fold'},
            {'header': 'err_filepath', 'overflow': 'fold'},
        ],
        [
            [
                dissector.slug,
                str(dissector_ctx.out_filepath(dissector).resolve()),
                str(dissector_ctx.err_filepath(dissector).resolve()),
            ]
            for dissector in dissectors
        ],
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
        '--parallel-surgeons',
        type=int,
        default=1,
        help="Define how many surgeons are running in parallel per dissector",
    )
    dissect.add_argument(
        '--parallel-dissectors',
        type=int,
        default=1,
        help="Define how many dissectors are running in parallel",
    )
    dissect.add_argument(
        'target', type=Path, help="Filepath or directory to dissect"
    )
    dissect.add_argument(
        'output_directory', type=Path, help="Dissector output directory"
    )
    dissect.set_defaults(func=_dissect_cmd)
