"""list command implementation"""

from edf_plasma_core.dissector import get_dissectors

from .abc import display_table


def _list_cmd(args):
    display_table(
        args.format,
        ['slug', 'tags', 'description'],
        (
            [
                dissector.slug,
                ','.join(sorted(tag.value for tag in dissector.tags)),
                dissector.description,
            ]
            for dissector in get_dissectors()
        ),
        show_header=False,
    )


def setup_command(cmd):
    """Setup init command parser"""
    list_ = cmd.add_parser('list', aliases=['ls'], help="List dissectors")
    list_.set_defaults(func=_list_cmd)
