FROM debian:wheezy

MAINTAINER Alex Chan <alexchan@projectcalico.org>

RUN apt-get update
RUN echo "APT::GET::Assume-Yes \"true\";" >> /etc/apt/apt.conf

# tox installs python-posix-spawn and python-etcd from Git
RUN apt-get install git

# These packages are required for installing python-cryptography
RUN apt-get install libffi-dev python-dev

# These packages enable apt-add-repository, which we need for our
# Python 2.6 and PyPy tests.
RUN apt-get install python-software-properties software-properties-common

# The python-cryptography module requires PyPy >= 2.6, but the standard
# repos only go up to 2.2.1.  This repo includes PyPy 2.6.
#RUN apt-add-repository ppa:pypy/ppa && apt-get update
RUN apt-get install pypy pypy-dev

# Install Python 2.6
RUN apt-add-repository ppa:fkrull/deadsnakes && apt-get update
RUN apt-get install -y python2.6 python2.6-dev

# Install test dependencies
RUN apt-get install python-pip
RUN pip install coverage==4.0a1 eventlet tox

COPY . /calico
WORKDIR /calico

CMD ["./run-unit-test.sh", "-r"]
