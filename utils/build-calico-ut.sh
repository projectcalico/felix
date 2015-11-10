#!/bin/bash

apt-get update

# tox installs python-posix-spawn and python-etcd from Git
apt-get install -y git

# These packages are required for installing python-cryptography
apt-get install -y libffi-dev python-dev

# These packages enable apt-add-repository, which we need for our
# Python 2.6 and PyPy tests.
apt-get install -y python-software-properties software-properties-common

# The python-cryptography module requires PyPy >= 2.6, but the standard
# repos only go up to 2.2.1.  This repo includes PyPy 2.6.
apt-add-repository ppa:pypy/ppa
apt-get update
apt-get install -y pypy pypy-dev

# Install Python 2.6
apt-add-repository ppa:fkrull/deadsnakes
apt-get update
apt-get install -y python2.6-minimal python2.6-dev

# Install test dependencies
apt-get install -y python-pip
pip install coverage==4.0a1 eventlet tox

# Now use tox to set up the environent, but not run any tests.  This
# allows us to get rid of build deps afterwards, for a smaller container
# image.
mkdir -p /calico/calico
cp /setup.py /calico/setup.py
cp /tox.ini /calico/tox.ini
touch /calico/calico/__init__.py
cd /calico; tox --notest

# Now remove all the packages required for installing tox's deps
apt-get remove -y libffi-dev python-dev python-pip \
                  python-software-properties software-properties-common \
                  pypy-dev python2.6-dev
apt-get autoremove -y
apt-get clean
