"""Tag"""

from enum import Enum


class Tag(Enum):
    """Tag"""

    # operating systems
    IOS = 'ios'
    LINUX = 'linux'
    DARWIN = 'darwin'
    ANDROID = 'android'
    WINDOWS = 'windows'
    # artifact natures
    PE = 'pe'
    ELF = 'elf'
    MVT = 'mvt'
    PCAP = 'pcap'
    GENERIC = 'generic'
    MEMDUMP = 'memdump'
    SYSDIAG = 'sysdiag'
    DUMPSTATE = 'dumpstate'
