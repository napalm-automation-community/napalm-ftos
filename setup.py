"""setup.py file."""

from setuptools import setup, find_packages

__author__ = 'Reinier Schoof <reinier@skoef.nl>'

with open("README.md", "r") as fh:
    long_description = fh.read()


def parse_reqs(file_path):
    """Parse requirements from file."""
    with open(file_path, 'rt') as fobj:
        lines = map(str.strip, fobj)
        lines = filter(None, lines)
        lines = filter(lambda x: not x.startswith("#"), lines)
        return tuple(lines)


setup(
    name="napalm-ftos",
    version="0.1.2",
    packages=find_packages(),
    author="Reinier Schoof, Manuel Holtgrewe",
    author_email="reinier@skoef.nl, manuel.holtgrewe@bih-charite.de",
    description="NAPALM driver for Force10 FTOS",
    long_description_content_type="text/markdown",
    long_description=long_description,
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 3',
         'Programming Language :: Python :: 3.6',
         'Programming Language :: Python :: 3.7',
         'Programming Language :: Python :: 3.8',
        'Operating System :: POSIX :: Linux',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation-community/napalm-ftos",
    include_package_data=True,
    install_requires=parse_reqs('requirements.txt'),
)
