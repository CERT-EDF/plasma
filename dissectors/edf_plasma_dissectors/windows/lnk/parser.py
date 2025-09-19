"""MS-SHLLINK parsing

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943
"""

from edf_plasma_core.dissector import DissectionContext
from edf_plasma_core.helper.datetime import macb_groups, to_iso_fmt, with_utc

from .helper import check_file_signature_file_object, open_file_object

MS_SHLLNK_SIG = b'\x4c\x00\x00\x00'


def lnk_records(lnk_obj):
    """Extract macb grouped links records"""
    for dtv, macb_string in macb_groups(
        with_utc(lnk_obj.file_modification_time),
        with_utc(lnk_obj.file_access_time),
        with_utc(lnk_obj.file_creation_time),
        with_utc(lnk_obj.file_creation_time),
    ):
        yield {
            'lnk_time': to_iso_fmt(dtv),
            'lnk_macb': macb_string,
            'lnk_desc': lnk_obj.description or '',
            'lnk_drive_sn': lnk_obj.drive_serial_number or -1,
            'lnk_drive_type': lnk_obj.drive_type or -1,
            'lnk_target': lnk_obj.local_path or '',
            'lnk_target_sz': lnk_obj.file_size or -1,
            'lnk_target_attrib': lnk_obj.file_attribute_flags or '',
            'lnk_workdir': lnk_obj.working_directory or '',
            'lnk_net_loc': lnk_obj.network_path or '',
            'lnk_env_loc': lnk_obj.environment_variables_location or '',
            'lnk_icon_loc': lnk_obj.icon_location or '',
            'lnk_machine_id': lnk_obj.machine_identifier or '',
            'lnk_vol_label': lnk_obj.volume_label or '',
        }


def parse_lnk_bytes(bytes_io, ctx: DissectionContext):
    """Parse bytes io instance as LNK object"""
    if not check_file_signature_file_object(bytes_io):
        return
    try:
        lnk_obj = open_file_object(bytes_io)
    except OSError as exc:
        ctx.register_error(f"liblnk exception: {exc}")
        return
    yield from lnk_records(lnk_obj)
