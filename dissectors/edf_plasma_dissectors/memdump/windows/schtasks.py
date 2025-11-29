"""Windows Scheduled Tasks Memory Dissector"""

from edf_plasma_core.concept import Tag
from edf_plasma_core.dissector import (
    DissectionContext,
    Dissector,
    register_dissector,
)
from edf_plasma_core.helper.table import Column, DataType
from edf_plasma_core.helper.typing import RecordIterator

from ..helper import (
    run_volatility3_plugin,
    select_memdump_impl,
    setup_volatility3_framework,
)

_VOL_PLUGIN = 'windows.registry.scheduled_tasks.ScheduledTasks'
_VOL_FIELDS_MAPPING = {
    'Display Name': 'display_name',
    'Action': 'action',
    'Action Arguments': 'action_args',
    'Action Context': 'action_ctx',
    'Action Type': 'action_type',
    'Creation Time': 'creation_time',
    'Enabled': 'enabled',
    'Key Name': 'key_name',
    'Last Run Time': 'last_run_time',
    'Last Successful Run Time': 'last_success_time',
    'Principal ID': 'principal_id',
    'Task Name': 'task_name',
    'Trigger Description': 'trigger_desc',
    'Trigger Type': 'trigger_type',
    'Working Directory': 'workind_dir',
}


def _dissect_impl(ctx: DissectionContext) -> RecordIterator:
    setup_volatility3_framework()
    for record in run_volatility3_plugin(ctx.filepath, _VOL_PLUGIN):
        yield {val: record[key] for key, val in _VOL_FIELDS_MAPPING.items()}


DISSECTOR = Dissector(
    slug='memdump_windows_schtasks',
    tags={Tag.MEMDUMP, Tag.WINDOWS},
    columns=[
        Column('display_name', DataType.STR),
        Column('action', DataType.STR),
        Column('action_args', DataType.STR),
        Column('action_ctx', DataType.STR),
        Column('action_type', DataType.STR),
        Column('creation_time', DataType.STR),
        Column('enabled', DataType.BOOL),
        Column('key_name', DataType.STR),
        Column('last_run_time', DataType.STR),
        Column('last_success_time', DataType.STR),
        Column('principal_id', DataType.STR),
        Column('task_name', DataType.STR),
        Column('trigger_desc', DataType.STR),
        Column('trigger_type', DataType.STR),
        Column('workind_dir', DataType.STR),
    ],
    description="Windows scheduled tasks from memory dump",
    select_impl=select_memdump_impl,
    dissect_impl=_dissect_impl,
)
register_dissector(DISSECTOR)
