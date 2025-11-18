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
    'wrapt==1.16.0',
    'Deprecated>=1.2.13,<2.0.0',
    'pytz',
    "requests>=2.19.1, ==2.*",
    'crcmod>=1.7',
    'six',
]

# 开发、测试过程中需要的依赖
DEV_REQUIRES = [
    'flake8>=3.5.0,<4.0.0',
    'mypy>=0.620; python_version>="3.4"',
    'tox>=3.0.0,<4.0.0',
    'isort>=4.0.0,<5.0.0',
    'pytest>=4.0.0,<5.0.0',
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
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='boilerplate',
    packages=find_packages(exclude=['docs', 'tests']),
    install_requires=REQUIRES,
    package_data={
        # for PEP484 & PEP561
        NAME: ['py.typed', '*.pyi'],
    },
)
