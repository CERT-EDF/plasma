"""Table helper"""

from dataclasses import dataclass
from enum import Enum

from .typing import StringList


class DataType(Enum):
    """Table datatypes"""

    STR = 'str'
    INT = 'int'
    BOOL = 'bool'
    INET = 'inet'
    FLOAT = 'float'


DataTypeList = list[DataType]


@dataclass
class Column:
    """Column"""

    name: str
    data_type: DataType


ColumnList = list[Column]


@dataclass
class Table:
    """Table"""

    columns: ColumnList

    def __len__(self):
        return len(self.columns)

    @property
    def names(self) -> StringList:
        """Column names"""
        return [column.name for column in self.columns]

    @property
    def data_types(self) -> DataTypeList:
        """Column data types"""
        return [column.data_type for column in self.columns]
