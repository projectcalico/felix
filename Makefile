all: pyinstaller deb rpm

DEB_VERSION:=$(shell grep calico debian/changelog | \
                     head -n 1 | cut -d '(' -f 2 | cut -d ')' -f 1 | \
                     cut -d '-' -f 1)
DEB_VERSION_TRUSTY:=$(shell echo $(DEB_VERSION) | sed "s/__STREAM__/trusty/g")
DEB_VERSION_XENIAL:=$(shell echo $(DEB_VERSION) | sed "s/__STREAM__/xenial/g")
PY_VERSION:=$(shell python2.7 python/setup.py --version 2>>/dev/null)
GIT_COMMIT:=$(shell git rev-parse HEAD)
GIT_COMMIT_SHORT:=$(shell git rev-parse --short HEAD)
GIT_DESCRIPTION:=$(shell git describe --tags)
DATE:=$(shell date -u +'%FT%T%z')

BUNDLE_FILENAME:=dist/calico-felix-${PY_VERSION}-git-${GIT_COMMIT_SHORT}.tgz

GO_FILES:=$(shell find go/ -type f -name '*.go')
PY_FILES:=python/calico/felix/felixbackend_pb2.py $(shell find python/ docs/  -type f -name '*.py')
MY_UID:=$(shell id -u)
MY_GID:=$(shell id -g)

# Build a docker image used for building our go code into a binary.
.PHONY: golang-build-image
golang-build-image:
	$(MAKE) docker-build-images/passwd docker-build-images/group
	cd docker-build-images && docker build -f golang-build.Dockerfile -t calico-golang-build .

# Build a docker image used for building debs for trusty.
.PHONY: trusty-build-image
trusty-build-image:
	cd docker-build-images && docker build -f ubuntu-trusty-build.Dockerfile -t calico-trusty-build .

# Build a docker image used for building debs for xenial.
.PHONY: xenial-build-image
xenial-build-image:
	cd docker-build-images && docker build -f ubuntu-xenial-build.Dockerfile -t calico-xenial-build .

# Construct a passwd file to embed in the centos docker image with the current
# user's username.  (The RPM build tools fail if they can't find the current
# user and group.)
.PHONY: docker-build-images/passwd
docker-build-images/passwd:
	echo "user:x:$(MY_UID):$(MY_GID):Build user:/:/bin/bash" > docker-build-images/passwd.new
	# Only update the file if it has changed to avoid cascading rebuilds.
	diff -q docker-build-images/passwd.new \
	        docker-build-images/passwd || \
	  mv docker-build-images/passwd.new docker-build-images/passwd
	rm -f docker-build-images/passwd.new

# Construct a group file to embed in the centos docker image with the current
# user's username.  (The RPM build tools fail if they can't find the current
# user and group.)
.PHONY: docker-build-images/group
docker-build-images/group:
	echo "user:x:$(MY_GID):" > docker-build-images/group.new
	# Only update the file if it has changed to avoid cascading rebuilds.
	diff -q docker-build-images/group.new \
	        docker-build-images/group || \
	  mv docker-build-images/group.new docker-build-images/group
	rm -f docker-build-images/group.new

# Construct a docker image for building Centos 7 RPMs.
.PHONY: centos7-build-image
centos7-build-image:
	$(MAKE) docker-build-images/passwd docker-build-images/group
	cd docker-build-images && docker build -f centos7-build.Dockerfile -t calico-centos7-build .

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
	    pip install -U hypothesis mock nose unittest2 && \
	    pip install -e ./python

DOCKER_RUN:=docker run --rm --user $(MY_UID):$(MY_GID) -v $${PWD}:/code

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

.PHONY: update-vendor
update-vendor:
	cd go && glide up

go/vendor go/vendor/.up-to-date: go/glide.lock
	# Make sure the docker image exists.  Since it's a PHONY, we can't add it
	# as a dependency or this job will run every time.  Docker does its own
	# freshness checking for us.
	$(MAKE) golang-build-image
	mkdir -p $$HOME/.glide
	$(DOCKER_RUN) \
	    --net=host \
	    -v $${PWD}:/go/src/github.com/projectcalico/calico:rw \
	    -v $$HOME/.glide:/.glide:rw \
	    -w /go/src/github.com/projectcalico/calico/go \
	    calico-golang-build \
	    glide install --strip-vcs --strip-vendor
	touch go/vendor/.up-to-date

LDFLAGS:=-ldflags "-X github.com/projectcalico/calico/go/felix/buildinfo.Version=$(GIT_DESCRIPTION) \
        -X github.com/projectcalico/calico/go/felix/buildinfo.BuildDate=$(DATE) \
        -X github.com/projectcalico/calico/go/felix/buildinfo.GitRevision=$(GIT_COMMIT) \
        -B 0x$(GIT_COMMIT)"

bin/calico-felix: go/felix/proto/felixbackend.pb.go \
                  $(GO_FILES) \
                  go/vendor/.up-to-date \
                  docker-build-images/golang-build.Dockerfile
	# Make sure the docker image exists.  Since it's a PHONY, we can't add it
	# as a dependency or this job will run every time.  Docker does its own
	# freshness checking for us.
	$(MAKE) golang-build-image
	mkdir -p bin
	$(DOCKER_RUN) \
	    -v $${PWD}:/go/src/github.com/projectcalico/calico:rw \
	    calico-golang-build \
	    go build -o $@ $(LDFLAGS) "./go/felix/felix.go"

dist/calico-felix/calico-iptables-plugin dist/calico-felix/calico-felix: $(PY_FILES) docker-build-images/pyi/* bin/calico-felix
	# Rebuild the docker container with the latest code.
	docker build -t calico-pyi-build -f docker-build-images/pyi/Dockerfile .

	# Output version information
	echo "Calico version: $(PY_VERSION) \n" \
	     "Git revision: $(GIT_COMMIT)\n" > version.txt

	# Run pyinstaller to generate the distribution directory.
	echo "Running pyinstaller"
	$(DOCKER_RUN) \
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

# Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/onsi/ginkgo/ginkgo

.PHONY: python-ut
python-ut: python/calico/felix/felixbackend_pb2.py
	cd python && ./run-unit-test.sh

.PHONY: go-ut
go-ut: golang-build-image go/vendor/.up-to-date go/felix/proto/felixbackend.pb.go
	$(DOCKER_RUN) \
	    --net=host \
	    -v $${PWD}:/go/src/github.com/projectcalico/calico:rw \
	    -v $$HOME/.glide:/.glide:rw \
	    -w /go/src/github.com/projectcalico/calico/go \
	    calico-golang-build \
	    ginkgo -v -r

.PHONY: ut
ut: python-ut go-ut

.PHONY: clean
clean:
	rm -rf bin \
	       dist \
	       build \
	       python/calico/felix/felixbackend_pb2.py \
	       go/felix/proto/felixbackend.pb.go \
	       docker-build-images/passwd \
	       docker-build-images/group
