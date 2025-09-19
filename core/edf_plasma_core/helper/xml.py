"""XML helper"""

from collections.abc import Iterator
from pathlib import Path
from pyexpat import EXPAT_VERSION
from xml.etree import ElementTree as ET

from .logging import get_logger

# according to docs.python.org/fr/3/library/xml.html#xml-vulnerabilities
_LOGGER = get_logger('core.helper.xml')
_MIN_SAFE_EXPAT_VERSION = '2.4.1'


def check_xml_parser_safety() -> bool:
    """Determine if runtime XML parser is safe"""
    version = EXPAT_VERSION.split('_', 1)[-1]
    is_safe = bool(version >= _MIN_SAFE_EXPAT_VERSION)
    if not is_safe:
        _LOGGER.warning(
            "runtime XML parser is not safe, expat version is %s", version
        )
    return is_safe


def check_xml_file(filepath: Path) -> bool:
    """Determine if given filepath contains valid XML data"""
    try:
        ET.parse(str(filepath))
    except ET.ParseError:
        return False
    return True


def check_xml_string(string: str) -> bool:
    """Determine if given string contains valid XML data"""
    try:
        ET.fromstring(string)
    except ET.ParseError:
        return False
    return True


def get_child(
    p_element: ET.Element, tag: str, required: bool = False
) -> ET.Element | None:
    """Find a specific child element matching given tag"""
    c_element = p_element.find(f'./{{*}}{tag}')
    if c_element is None and required:
        raise ValueError(f"required child element is missing: {tag}")
    if c_element is None:
        return None
    return c_element


def get_children(
    p_element: ET.Element, tag: str | None = None, required: bool = False
) -> Iterator[ET.Element]:
    """Find all children elements matching given tag"""
    found = False
    pattern = './*'
    if tag is not None:
        pattern = f'./{{*}}{tag}'
    for c_element in p_element.findall(pattern):
        found = True
        yield c_element
    if required and not found:
        raise ValueError(f"required child element is missing: {tag}")


def get_text(element: ET.Element | None) -> str | None:
    """Get element text or none"""
    if element is None:
        return None
    return element.text


def get_attr(element: ET.Element | None, attribute: str) -> str | None:
    """Get element attribute or none"""
    if element is None:
        return None
    return element.get(attribute, None)


def element_to_string(element: ET.Element) -> str:
    """Convert element instance to a string"""
    ET.indent(element, space='', level=0)
    return ET.tostring(element, encoding='unicode')


def _strip_ns(element):
    if hasattr(element, 'tag'):
        element.tag = element.tag.split('}', 1)[-1]
    for child in get_children(element):
        _strip_ns(child)


class XMLSerializableAPI:
    """XML serializable interface"""

    @classmethod
    def from_element(cls, element: ET.Element):
        """Build instance from xml element"""
        raise NotImplementedError(
            "subclass failed to implement .from_element()"
        )

    @classmethod
    def from_string(cls, string: str):
        """Build instance from xml string"""
        try:
            element = ET.fromstring(string)
        except ET.ParseError:
            _LOGGER.exception("XML parsing error!")
            return None
        _strip_ns(element)
        return cls.from_element(element)

    @classmethod
    def from_filepath(cls, filepath: Path):
        """Build instance from XML data stored in filepath"""
        try:
            element = ET.parse(str(filepath))
        except ET.ParseError:
            _LOGGER.exception("XML parsing error!")
            return None
        _strip_ns(element)
        return cls.from_element(element)
