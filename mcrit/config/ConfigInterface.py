import copy
import logging
from dataclasses import asdict, dataclass, field


def default_field(obj):
    return field(default_factory=lambda: copy.copy(obj))


class ConfigInterface(object):

    ### global logging-config setup
    # Only do basicConfig if no handlers have been configured
    LOG_PATH: str = "./"
    LOG_LEVEL: ... = logging.INFO
    LOG_FORMAT: str = "%(asctime)-15s: %(name)-32s - %(message)s"

    def __post_init__(self):
        if len(logging._handlerList) == 0:
            logging.basicConfig(level=self.LOG_LEVEL, format=self.LOG_FORMAT)

    def toDict(self):
        result = asdict(self)
        delkeys = [k for k in result.keys() if k.startswith("LOG_")]
        for key in delkeys:
            del result[key]
        return result

    @classmethod
    def fromDict(cls, config_dict):
        return cls(**config_dict)
