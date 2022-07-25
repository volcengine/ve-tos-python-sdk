#! /usr/bin/env bash

set -e

PROJECT_ROOT=$(cd $(dirname ${BASH_SOURCE[0]}); pwd)

cd ${PROJECT_ROOT}
rm -rf .tox venv

virtualenv venv --python=python3 && source venv/bin/activate
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host=pypi.tuna.tsinghua.edu.cn -e .[dev]

tox

