import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyhaveibeenpwned",
    version="0.2.0",
    author="Shane Scott",
    author_email="shane@shanewilliamscott.com",
    description="Library to query HaveIBeenPwned.com with handling for CloudFlare anti-bot",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Hackman238/pyHaveIBeenPwned",
    packages=['pyhaveibeenpwned'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX :: Linux',
        'Topic :: Software Development :: Libraries',
    ],
    python_requires='>=3.9',
)
