from pathlib import Path
from setuptools import find_packages, setup

PACKAGE_NAME = "pyhaveibeenpwned"
README_PATH = Path(__file__).parent / "README.md"
VERSION_PATH = Path(__file__).parent / PACKAGE_NAME / "VERSION"

with README_PATH.open(encoding="utf-8") as fh:
    long_description = fh.read()
with VERSION_PATH.open(encoding="utf-8") as fh:
    version = fh.read().strip()

setup(
    name=PACKAGE_NAME,
    version=version,
    author="Shane Scott",
    author_email="shane@shanewilliamscott.com",
    description="Library to query HaveIBeenPwned and breach data providers",
    license="GPL-2.0-only",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Hackman238/pyHaveIBeenPwned",
    packages=find_packages(exclude=("tests", "venv")),
    package_data={PACKAGE_NAME: ["VERSION"]},
    install_requires=[
        "requests>=2.32.5",
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Topic :: Software Development :: Libraries',
    ],
    python_requires='>=3.9',
)
