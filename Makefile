all: pyinstaller

DEB_VERSION:=$(shell grep calico debian/changelog | \
                     head -n 1 | cut -d '(' -f 2 | cut -d ')' -f 1 | \
                     cut -d '-' -f 1)
GO_FILES:=$(shell find go/ -type f -name '*.go')
PY_FILES:=*.py calico/felix/felixbackend_pb2.py $(shell find calico/ docs/  -type f -name '*.py')
MY_UID:=$(shell id -u)

.PHONY: trusty-build-image
trusty-build-image:
	cd docker-build-images && docker build . -f ubuntu-trusty-build.Dockerfile -t calico-trusty-build

.PHONY: xenial-build-image
xenial-build-image:
	cd docker-build-images && docker build . -f ubuntu-xenial-build.Dockerfile -t calico-xenial-build


.PHONY: deb
deb: trusty-deb xenial-deb

.PHONY: trusty-deb
trusty-deb: dist/trusty/calico-felix_$(DEB_VERSION)_amd64.deb

.PHONY: xenial-deb
xenial-deb: dist/xenial/calico-felix_$(DEB_VERSION)_amd64.deb

DOCKER_RUN:=docker run --rm --user $(MY_UID)  -v $${PWD}:/code

dist/trusty/calico-felix_$(DEB_VERSION)_amd64.deb: dist/calico-felix/calico-felix
	$(MAKE) trusty-build-image
	$(DOCKER_RUN) -e DEB_VERSION=$(DEB_VERSION) \
	              calico-trusty-build debian/build-debs

dist/xenial/calico-felix_$(DEB_VERSION)_amd64.deb: dist/calico-felix/calico-felix
	$(MAKE) xenial-build-image
	$(DOCKER_RUN) -e DEB_VERSION=$(DEB_VERSION) \
	              calico-xenial-build debian/build-debs

.PHONY: update-vendor
update-vendor:
	cd go && glide up

go/felix/proto/felixbackend.pb.go: go/felix/proto/felixbackend.proto
	$(DOCKER_RUN) -v $${PWD}/go/felix/proto:/src:rw \
	              calico/protoc \
	              --gogofaster_out=. \
	              felixbackend.proto

calico/felix/felixbackend_pb2.py: go/felix/proto/felixbackend.proto
	$(DOCKER_RUN) -v $${PWD}/go/felix/proto:/src:rw \
	              -v $${PWD}/calico/felix/:/dst:rw \
	              calico/protoc \
	              --python_out=/dst/ \
	              felixbackend.proto

bin/calico-felix: go/felix/proto/felixbackend.pb.go $(GO_FILES)
	mkdir -p bin
	go build -o "$@" "./go/felix/felix.go"

dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix: $(PY_FILES) pyi/* bin/calico-felix
	./build-pyi-bundle.sh
	test -e dist/calico-felix/calico-iptables-plugin && touch dist/calico-felix/calico-iptables-plugin
	test -e dist/calico-felix/calico-felix && touch dist/calico-felix/calico-felix

.PHONY: pyinstaller
pyinstaller: dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix

.PHONY: clean
clean:
	rm -rf bin \
	       dist \
	       calico/felix/felixbackend_pb2.py \
	       go/felix/proto/felixbackend.pb.go
