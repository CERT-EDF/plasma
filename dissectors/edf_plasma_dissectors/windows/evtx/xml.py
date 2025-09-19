"""ETVX XML elements"""

from dataclasses import dataclass
from enum import Enum, auto

from edf_plasma_core.helper.logging import get_logger
from edf_plasma_core.helper.xml import (
    XMLSerializableAPI,
    element_to_string,
    get_attr,
    get_child,
    get_children,
    get_text,
)

_LOGGER = get_logger('dissectors.microsoft.evtx.xml')


@dataclass
class System(XMLSerializableAPI):
    """System element"""

    channel: str | None = None
    provider: str | None = None
    computer: str | None = None
    event_id: int | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        event_id = get_text(get_child(element, 'EventID'))
        if event_id is not None:
            event_id = int(event_id)
        return cls(
            channel=get_text(get_child(element, 'Channel')),
            provider=get_attr(get_child(element, 'Provider'), 'Name'),
            computer=get_text(get_child(element, 'Computer')),
            event_id=event_id,
        )


class EventDataType(Enum):
    """Type of event data"""

    EVENT_DATA = auto()
    USER_DATA = auto()
    DEBUG_DATA = auto()
    BINARY_DATA = auto()
    ERROR_DATA = auto()


def _parse_data(element):
    data = get_child(element, 'EventData')
    if data is not None:
        return EventDataType.EVENT_DATA, data
    data = get_child(element, 'UserData')
    if data is not None:
        return EventDataType.USER_DATA, data
    data = get_child(element, 'DebugData')
    if data is not None:
        return EventDataType.DEBUG_DATA, data
    data = get_child(element, 'BinaryEventData')
    if data is not None:
        return EventDataType.BINARY_DATA, data
    data = get_child(element, 'DissectionErrorData')
    if data is not None:
        return EventDataType.ERROR_DATA, data
    _LOGGER.warning(
        "cannot find event data in %s",
        [item.tag for item in get_children(element)],
    )
    return None, None


@dataclass
class Event(XMLSerializableAPI):
    """Event element"""

    system: System
    datatype: EventDataType
    data: str

    @classmethod
    def from_element(cls, element):
        system = System.from_element(get_child(element, 'System'))
        datatype, data = _parse_data(element)
        data = element_to_string(data)
        return cls(system=system, datatype=datatype, data=data)
