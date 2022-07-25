# coding: utf-8

import io
import os

from setuptools import find_packages, setup

# 包元信息
NAME = 'tos'  #
DESCRIPTION = 'Volc TOS (Tinder Object Storage) SDK'
URL = 'https://www.volcengine.com/'  #
EMAIL = 'sunyushan.jason@bytedance.com'
AUTHOR = 'sunyushan'

# 项目运行需要的依赖
REQUIRES = [
    'six>=1.11.0,<2.0.0',
    'requests>=2.19.1,<3.0.0',
    'pytz>=2013.6,<2022.1',
    'crcmod>=1.7,<2.0',
    'Deprecated>=1.2.13,<2.0.0',
    'pytest-cov>=3.0.0,<4.0.0',
    'pytest>=4.0.0,<5.0.0',
]

# 开发、测试过程中需要的依赖
DEV_REQUIRES = [
    'flake8>=3.5.0,<4.0.0',
    'mypy>=0.620; python_version>="3.4"',
    'tox>=3.0.0,<4.0.0',
    'isort>=4.0.0,<5.0.0',
    'pytest>=4.0.0,<5.0.0'
]

here = os.path.abspath(os.path.dirname(__file__))

try:
    with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = '\n' + f.read()
except IOError:
    long_description = DESCRIPTION

about = {}
with io.open(os.path.join(here, NAME, '__version__.py')) as f:
    exec(f.read(), about)

setup(
    name=NAME,  # add the 'byted' prefix for package name
    version=about['__version__'],
    description=DESCRIPTION,
    long_description=long_description,
    long_description_content_type='text/markdown',
    author=AUTHOR,
    author_email=EMAIL,
    url=URL,
    classifiers=[
        # Trove classifiers
        # Full list: https://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='boilerplate',
    packages=find_packages(exclude=['docs', 'tests']),
    install_requires=REQUIRES,
    tests_require=[
        'pytest>=4.0.0,<5.0.0'
    ],
    python_requires='>3.5',
    package_data={
        # for PEP484 & PEP561
        NAME: ['py.typed', '*.pyi'],
    },
)
