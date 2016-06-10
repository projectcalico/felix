FROM ubuntu:14.04
MAINTAINER Alex Chan <alexchan@projectcalico.org>

ADD ./utils/build-calico-ut.sh /build-calico-ut.sh
ADD ./setup.py /setup.py
ADD ./tox.ini /tox.ini
RUN sh /build-calico-ut.sh

COPY . /calico
WORKDIR /calico

CMD ["./run-unit-test.sh", "-r"]
