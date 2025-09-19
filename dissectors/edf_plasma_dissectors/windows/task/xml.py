"""Microsoft Scheduled Task XML Elements"""

from dataclasses import dataclass

from edf_plasma_core.helper.typing import StringList
from edf_plasma_core.helper.xml import (
    XMLSerializableAPI,
    get_child,
    get_children,
    get_text,
)


@dataclass
class RegistrationInfo(XMLSerializableAPI):
    """RegistrationInfo element"""

    uri: str | None = None
    security_desc: str | None = None
    source: str | None = None
    date: str | None = None
    author: str | None = None
    version: str | None = None
    description: str | None = None
    documentation: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            uri=get_text(get_child(element, 'URI')),
            security_desc=get_text(get_child(element, 'SecurityDescriptor')),
            source=get_text(get_child(element, 'Source')),
            date=get_text(get_child(element, 'Date')),
            author=get_text(get_child(element, 'Author')),
            version=get_text(get_child(element, 'Version')),
            description=get_text(get_child(element, 'Description')),
            documentation=get_text(get_child(element, 'Documentation')),
        )


@dataclass
class Repetition(XMLSerializableAPI):
    """Repetition element"""

    interval: str
    duration: str | None = None
    stop_at_duration_end: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            interval=get_text(get_child(element, 'Interval', True)),
            duration=get_text(get_child(element, 'Duration')),
            stop_at_duration_end=get_text(
                get_child(element, 'StopAtDurationEnd')
            ),
        )


def _parse_trigger_generic(element):
    return {
        'enabled': get_text(get_child(element, 'Enabled')),
        'start_boundary': get_text(get_child(element, 'StartBoundary')),
        'end_boundary': get_text(get_child(element, 'EndBoundary')),
        'repetition': Repetition.from_element(
            get_child(element, 'Repetition')
        ),
        'execution_time_limit': get_text(
            get_child(element, 'ExecutionTimeLimit')
        ),
    }


@dataclass
class BootTrigger(XMLSerializableAPI):
    """BootTrigger element"""

    delay: str | None = None
    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        kwargs['delay'] = get_text(get_child(element, 'Delay'))
        return cls(**kwargs)


@dataclass
class ScheduleByDay(XMLSerializableAPI):
    """ScheduleByDay element"""

    days_interval: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(days_interval=get_text(get_child(element, 'DaysInterval')))


def _parse_months(element):
    if element is None:
        return None
    return [
        month.tag.split('}', 1)[-1]
        for month in get_children(element, required=True)
    ]


def _parse_days_of_the_month(element):
    if element is None:
        return None
    return [
        get_text(day) for day in get_children(element, 'Day', required=True)
    ]


@dataclass
class ScheduleByMonth(XMLSerializableAPI):
    """ScheduleByMonth element"""

    months: StringList | None = None
    days_of_the_month: StringList | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            months=_parse_months(get_child(element, 'Months')),
            days_of_the_month=_parse_days_of_the_month(
                get_child(element, 'DaysOfTheMonth')
            ),
        )


def _parse_weeks(element):
    if element is None:
        return None
    return [get_text(day) for day in get_children(element, 'Week')]


def _parse_days_of_the_week(element):
    if element is None:
        return None
    return [day.tag.split('}', 1)[-1] for day in get_children(element)]


@dataclass
class ScheduleByMonthDayOfWeek(XMLSerializableAPI):
    """ScheduleByMonthDayOfWeek element"""

    months: StringList | None = None
    weeks: StringList | None = None
    days_of_the_week: StringList | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            months=_parse_months(get_child(element, 'Months')),
            weeks=_parse_weeks(get_child(element, 'Weeks')),
            days_of_the_week=_parse_days_of_the_week(
                get_child(element, 'DaysOfTheWeek')
            ),
        )


@dataclass
class ScheduleByWeek(XMLSerializableAPI):
    """ScheduleByWeek element"""

    weeks_interval: str | None = None
    days_of_the_week: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            weeks_interval=get_text(get_child(element, 'WeeksInterval')),
            days_of_the_week=_parse_days_of_the_week(
                get_child(element, 'DaysOfTheWeek')
            ),
        )


@dataclass
class CalendarTrigger(XMLSerializableAPI):
    """CalendarTrigger element"""

    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None
    schedule_by_day: ScheduleByDay | None = None
    schedule_by_month: ScheduleByMonth | None = None
    schedule_by_month_day_of_week: ScheduleByMonthDayOfWeek | None = None
    schedule_by_week: ScheduleByWeek | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        kwargs['schedule_by_day'] = ScheduleByDay.from_element(
            get_child(element, 'ScheduleByDay')
        )
        kwargs['schedule_by_month'] = ScheduleByMonth.from_element(
            get_child(element, 'ScheduleByMonth')
        )
        kwargs['schedule_by_month_day_of_week'] = (
            ScheduleByMonthDayOfWeek.from_element(
                get_child(element, 'ScheduleByMonthDayOfWeek')
            )
        )
        kwargs['schedule_by_week'] = ScheduleByWeek.from_element(
            get_child(element, 'ScheduleByWeek')
        )
        return cls(**kwargs)


@dataclass
class EventTrigger(XMLSerializableAPI):
    """EventTrigger element"""

    delay: str | None = None
    subscription: str | None = None
    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        kwargs['delay'] = get_text(get_child(element, 'Delay'))
        kwargs['subscription'] = get_text(get_child(element, 'Subscription'))
        return cls(**kwargs)


@dataclass
class IdleTrigger(XMLSerializableAPI):
    """IdleTrigger element"""

    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        return cls(**kwargs)


@dataclass
class LogonTrigger(XMLSerializableAPI):
    """LogonTrigger element"""

    delay: str | None = None
    user_id: str | None = None
    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        kwargs['delay'] = get_text(get_child(element, 'Delay'))
        kwargs['user_id'] = get_text(get_child(element, 'UserId'))
        return cls(**kwargs)


@dataclass
class RegistrationTrigger(XMLSerializableAPI):
    """RegistrationTrigger element"""

    delay: str | None = None
    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        kwargs['delay'] = get_text(get_child(element, 'Delay'))
        return cls(**kwargs)


@dataclass
class TimeTrigger(XMLSerializableAPI):
    """TimeTrigger element"""

    random_delay: str | None = None
    enabled: str | None = None
    start_boundary: str | None = None
    end_boundary: str | None = None
    repetition: Repetition | None = None
    execution_time_limit: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        kwargs = _parse_trigger_generic(element)
        kwargs['random_delay'] = get_text(get_child(element, 'RandomDelay'))
        return cls(**kwargs)


@dataclass
class Principal(XMLSerializableAPI):
    """Principal element"""

    user_id: str | None = None
    logon_type: str | None = None
    group_id: str | None = None
    display_name: str | None = None
    run_level: str | None = None
    process_token_sid_type: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            user_id=get_text(get_child(element, 'UserId')),
            logon_type=get_text(get_child(element, 'LogonType')),
            group_id=get_text(get_child(element, 'GroupId')),
            display_name=get_text(get_child(element, 'DisplayName')),
            run_level=get_text(get_child(element, 'RunLevel')),
            process_token_sid_type=get_text(
                get_child(element, 'ProcessTokenSidType')
            ),
        )


@dataclass
class ComHandler(XMLSerializableAPI):
    """ComHandler element"""

    class_id: str
    data: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            class_id=get_text(get_child(element, 'ClassId', True)),
            data=get_text(get_child(element, 'Data')),
        )


@dataclass
class Exec(XMLSerializableAPI):
    """Exec element"""

    command: str
    arguments: str | None = None
    working_dir: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            command=get_text(get_child(element, 'Command', True)),
            arguments=get_text(get_child(element, 'Arguments')),
            working_dir=get_text(get_child(element, 'WorkingDirectory')),
        )


@dataclass
class SendEmail(XMLSerializableAPI):
    """SendEmail element"""

    server: str
    subject: str | None = None
    to_: str | None = None
    cc_: str | None = None
    bcc: str | None = None
    reply_to: str | None = None
    from_: str | None = None
    body: str | None = None

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            server=get_text(get_child(element, 'Server', True)),
            subject=get_text(get_child(element, 'Subject')),
            to_=get_text(get_child(element, 'To')),
            cc_=get_text(get_child(element, 'Cc')),
            bcc=get_text(get_child(element, 'Bcc')),
            reply_to=get_text(get_child(element, 'ReplyTo')),
            from_=get_text(get_child(element, 'From')),
            body=get_text(get_child(element, 'Body')),
        )


@dataclass
class ShowMessage(XMLSerializableAPI):
    """ShowMessage element"""

    title: str
    body: str

    @classmethod
    def from_element(cls, element):
        if element is None:
            return None
        return cls(
            title=get_text(get_child(element, 'Title', True)),
            body=get_text(get_child(element, 'Body', True)),
        )


_TRIGGER_CLS = {
    cls.__name__: cls
    for cls in (
        BootTrigger,
        CalendarTrigger,
        EventTrigger,
        IdleTrigger,
        LogonTrigger,
        RegistrationTrigger,
        TimeTrigger,
    )
}


def _parse_triggers(element):
    if element is None:
        return []
    triggers = []
    for trigger in get_children(element):
        trigger_cls = _TRIGGER_CLS.get(trigger.tag.split('}', 1)[-1])
        if not trigger_cls:
            continue
        triggers.append(trigger_cls.from_element(trigger))
    return triggers


def _parse_principals(principals):
    if principals is None:
        return []
    principal = get_child(principals, 'Principal')
    if not principal:
        return []
    return [Principal.from_element(principal)]


_ACTION_CLS = {
    cls.__name__: cls for cls in (ComHandler, Exec, SendEmail, ShowMessage)
}


def _parse_actions(element):
    if element is None:
        return []
    actions = []
    for action in get_children(element):
        action_cls = _ACTION_CLS.get(action.tag.split('}', 1)[-1])
        if not action_cls:
            continue
        actions.append(action_cls.from_element(action))
    return actions


@dataclass
class Task(XMLSerializableAPI):
    """Task element"""

    info: RegistrationInfo
    triggers: list[
        BootTrigger
        | CalendarTrigger
        | EventTrigger
        | IdleTrigger
        | LogonTrigger
        | RegistrationTrigger
        | TimeTrigger
    ]
    principals: list[Principal]
    actions: list[ComHandler | Exec | SendEmail | ShowMessage]

    @classmethod
    def from_element(cls, element):
        return cls(
            info=RegistrationInfo.from_element(
                get_child(element, 'RegistrationInfo')
            ),
            triggers=_parse_triggers(get_child(element, 'Triggers')),
            principals=_parse_principals(get_child(element, 'Principals')),
            actions=_parse_actions(get_child(element, 'Actions')),
        )
