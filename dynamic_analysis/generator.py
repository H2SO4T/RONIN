import random
import string
from abc import ABC
from dynamic_analysis.MIME import MIME


class Generator(ABC):
    @staticmethod
    def generate_string(generate_uri=False, size=8, chars=string.ascii_uppercase + string.digits +
                                      string.ascii_lowercase):
        if generate_uri:
            domains = [".com", ".org", ".net", ".int", ".gov", ".mil"]
            return ''.join(random.choice(chars) for x in range(size)).join(random.choice(domains))
        return ''.join(random.choice(chars) for x in range(size))

    @staticmethod
    def generate_numbers(a: int = -100, b: int = 100):
        return round(random.randrange(a, b, 1)*random.random(), 3)

    @staticmethod
    def generate_type():
        random.choice(MIME)

    @staticmethod
    def generate_types():
        return [list(MIME.values())]
