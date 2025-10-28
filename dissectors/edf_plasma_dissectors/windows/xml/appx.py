"""AppXManifest XML elements"""

from dataclasses import dataclass

from edf_plasma_core.helper.xml import XMLSerializableAPI, get_attr, get_child


@dataclass
class AppXManifestIdentity(XMLSerializableAPI):
    name: str
    publisher: str
    version: str
    architecture: str

    @classmethod
    def from_element(cls, element):
        return cls(
            name=get_attr(element, 'Name'),
            publisher=get_attr(element, 'Publisher'),
            version=get_attr(element, 'Version'),
            architecture=get_attr(element, 'DissectorArchitecture'),
        )


@dataclass
class AppXManifest(XMLSerializableAPI):

    identity: AppXManifestIdentity

    @classmethod
    def from_element(cls, element):
        identity = get_child(element, 'Identity')
        return cls(
            identity=AppXManifestIdentity.from_element(identity),
        )
