"""Windows task artifact dissector"""

from pathlib import Path

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import PathIterator, RecordIterator
from edf_plasma_core.helper.xml import check_xml_file, check_xml_parser_safety

from .xml.task import Task

_LOGGER = get_logger('dissectors.windows.task')


def _select_impl(directory: Path) -> PathIterator:
    if not check_xml_parser_safety():
        _LOGGER.warning("XML parser is not safe!")
        return
    for dirpath in directory.rglob('Tasks'):
        for filepath in dirpath.rglob('*'):
            if not filepath.is_file():
                continue
            if not check_xml_file(filepath):
                _LOGGER.warning("XML task parsing check failed: %s", filepath)
                continue
            yield filepath


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    task = Task.from_filepath(ctx.filepath)
    if not task:
        ctx.register_error("XML parsing error!")
        return
    yield {
        'task_uri': task.info.uri,
        'task_sec_desc': task.info.security_desc,
        'task_source': task.info.source,
        'task_date': task.info.date,
        'task_author': task.info.author,
        'task_version': task.info.version,
        'task_desc': task.info.description,
        'task_doc': task.info.documentation,
        'task_triggers': str(task.triggers),
        'taks_principals': str(task.principals),
        'task_actions': str(task.actions),
    }


DISSECTOR = Dissector(
    slug='windows_task',
    tags={Tag.WINDOWS},
    columns=[
        Column('task_uri', DataType.STR),
        Column('task_sec_desc', DataType.STR),
        Column('task_source', DataType.STR),
        Column('task_date', DataType.STR),
        Column('task_author', DataType.STR),
        Column('task_version', DataType.STR),
        Column('task_desc', DataType.STR),
        Column('task_doc', DataType.STR),
        Column('task_triggers', DataType.STR),
        Column('taks_principals', DataType.STR),
        Column('task_actions', DataType.STR),
    ],
    description="Scheduled tasks",
    select_impl=_select_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
