from importlib import resources


def _read_version():
    return resources.files(__package__).joinpath("VERSION").read_text(encoding="utf-8").strip()


__version__ = _read_version()
