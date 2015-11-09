FROM alpine

MAINTAINER Alex Chan <alexchan@projectcalico.org>

RUN apk update && apk add make python py-pip
RUN pip install Sphinx

RUN mkdir -p /calico/docs
WORKDIR /calico/docs

CMD ["make", "html"]
