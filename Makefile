all: pyinstaller

DEB_VERSION:=$(shell grep calico debian/changelog | \
                     head -n 1 | cut -d '(' -f 2 | cut -d ')' -f 1 | \
                     cut -d '-' -f 1)
DEB_VERSION_TRUSTY:=$(shell echo $(DEB_VERSION) | sed "s/__STREAM__/trusty/g")
DEB_VERSION_XENIAL:=$(shell echo $(DEB_VERSION) | sed "s/__STREAM__/xenial/g")
PY_VERSION:=$(shell python2.7 python/setup.py --version 2>>/dev/null)
GIT_COMMIT:=$(shell git rev-parse HEAD)
GIT_COMMIT_SHORT:=$(shell git rev-parse --short HEAD)

BUNDLE_FILENAME:=dist/calico-felix-${VERSION}-git-${GIT_COMMIT_SHORT}.tgz

GO_FILES:=$(shell find go/ -type f -name '*.go')
PY_FILES:=python/calico/felix/felixbackend_pb2.py $(shell find python/ docs/  -type f -name '*.py')
MY_UID:=$(shell id -u)
MY_GID:=$(shell id -g)
GIT_HASH:=$(shell git rev-parse HEAD)

.PHONY: trusty-build-image
trusty-build-image:
	cd docker-build-images && docker build . -f ubuntu-trusty-build.Dockerfile -t calico-trusty-build

.PHONY: xenial-build-image
xenial-build-image:
	cd docker-build-images && docker build . -f ubuntu-xenial-build.Dockerfile -t calico-xenial-build

.PHONY: docker-build-images/passwd
docker-build-images/passwd:
	echo "user:x:$(MY_UID):$(MY_GID):Build user:/:/bin/bash" > docker-build-images/passwd.new
	# Only update the file if it has changed to avoid cascading rebuilds.
	diff -q docker-build-images/passwd.new \
	        docker-build-images/passwd || \
	  mv docker-build-images/passwd.new docker-build-images/passwd
	rm -f docker-build-images/passwd.new

.PHONY: docker-build-images/group
docker-build-images/group:
	echo "user:x:$(MY_GID):" > docker-build-images/group.new
	# Only update the file if it has changed to avoid cascading rebuilds.
	diff -q docker-build-images/group.new \
	        docker-build-images/group || \
	  mv docker-build-images/group.new docker-build-images/group
	rm -f docker-build-images/group.new

.PHONY: centos7-build-image
centos7-build-image:
	$(MAKE) docker-build-images/passwd docker-build-images/group
	cd docker-build-images && docker build . -f centos7-build.Dockerfile -t calico-centos7-build

.PHONY: deb
deb: trusty-deb xenial-deb

.PHONY: trusty-deb
trusty-deb: dist/trusty/calico-felix_$(DEB_VERSION_TRUSTY)_amd64.deb

.PHONY: xenial-deb
xenial-deb: dist/xenial/calico-felix_$(DEB_VERSION_XENIAL)_amd64.deb

.PHONY: env
env:
	virtualenv env
	. env/bin/activate && \
	    pip install -U pip && \
	    pip install -e ./python

DOCKER_RUN:=docker run --rm --user $(MY_UID)  -v $${PWD}:/code

dist/trusty/calico-felix_$(DEB_VERSION_TRUSTY)_amd64.deb: dist/calico-felix/calico-felix debian/*
	$(MAKE) trusty-build-image
	$(DOCKER_RUN) -e DEB_VERSION=$(DEB_VERSION_TRUSTY) \
	              calico-trusty-build debian/build-debs

dist/xenial/calico-felix_$(DEB_VERSION_XENIAL)_amd64.deb: dist/calico-felix/calico-felix debian/*
	$(MAKE) xenial-build-image
	$(DOCKER_RUN) -e DEB_VERSION=$(DEB_VERSION_XENIAL) \
	              calico-xenial-build debian/build-debs

.PHONY: rpm
rpm: dist/calico-felix/calico-felix
	$(MAKE) centos7-build-image
	$(DOCKER_RUN) -e RPM_VERSION=$(RPM_VERSION) \
	              calico-centos7-build rpm/build-rpms

.PHONY: update-vendor
update-vendor:
	cd go && glide up

go/felix/proto/felixbackend.pb.go: go/felix/proto/felixbackend.proto
	$(DOCKER_RUN) -v $${PWD}/go/felix/proto:/src:rw \
	              calico/protoc \
	              --gogofaster_out=. \
	              felixbackend.proto

python/calico/felix/felixbackend_pb2.py: go/felix/proto/felixbackend.proto
	$(DOCKER_RUN) -v $${PWD}/go/felix/proto:/src:rw \
	              -v $${PWD}/python/calico/felix/:/dst:rw \
	              calico/protoc \
	              --python_out=/dst/ \
	              felixbackend.proto

go/vendor:
	$(MAKE) -C go vendor

bin/calico-felix: go/felix/proto/felixbackend.pb.go $(GO_FILES) go/vendor
	mkdir -p bin
	go build -o "$@" -ldflags "-B 0x$(GIT_HASH)" "./go/felix/felix.go"

dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix: $(PY_FILES) docker-build-images/pyi/* bin/calico-felix
	# Rebuild the docker container with the latest code.
	docker build -t calico-pyi-build -f docker-build-images/pyi/Dockerfile .
	echo "Build calico-pyi-build container"

	# Output version information
	echo "Calico version: $(PY_VERSION) \n" \
	     "Git revision: $(GIT_COMMIT)\n" > version.txt

	# Run pyinstaller to generate the distribution directory.
	echo "Running pyinstaller"
	docker run --user $(MY_UID) \
	       -ti \
	       --rm \
	       -v `pwd`:/code \
	       calico-pyi-build \
	       /code/docker-build-images/pyi/run-pyinstaller.sh

	# Check that the build succeeded and update the mtimes on the target files
	# since pyinstaller doesn't seem to do so.
	test -e dist/calico-felix/calico-iptables-plugin && touch dist/calico-felix/calico-iptables-plugin
	test -e dist/calico-felix/calico-felix && touch dist/calico-felix/calico-felix

$(BUNDLE_FILENAME): dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix
	tar -czf $(BUNDLE_FILENAME) -C dist calico-felix

.PHONY: pyinstaller
pyinstaller: $(BUNDLE_FILENAME)

.PHONY: clean
clean:
	rm -rf bin \
	       dist \
	       build \
	       python/calico/felix/felixbackend_pb2.py \
	       go/felix/proto/felixbackend.pb.go \
	       docker-build-images/passwd \
	       docker-build-images/group
