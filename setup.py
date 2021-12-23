# coding: utf-8

import os

from setuptools import find_packages, setup

# 项目运行需要的依赖
REQUIRES = [
    'six>=1.11.0,<2.0.0',
    'requests>=2.19.1,<3.0.0',
    'pytz>=2013.6'
]

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open('tos/__version__.py') as f:
    exec(f.read(), about)

with open('README.md', 'rb') as f:
    readme = f.read().decode('utf-8')

setup(
    name='tos',
    version=about['__version__'],
    description='Volc TOS (Tinder Storage Service) SDK',
    long_description=readme,
    url='https://www.volcengine.com/',
    classifiers=[
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    packages=['tos'],
    install_requires=REQUIRES,
)
