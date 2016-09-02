.PHONEY: all test ut update-vendor clean

BUILD_CONTAINER_NAME=calico/calicoctl_build_container
BUILD_CONTAINER_MARKER=calicoctl_build_container.created

default: all
all: test
test: ut

update-vendor:
	glide up

ut: bin/calicoctl
	./run-uts

felix/proto/felixbackend.pb.go: felix/proto/felixbackend.proto Makefile
	docker run -ti \
	           -v $${PWD}/felix/proto:/src:rw \
	           --rm protoc \
	           --gogofaster_out=. \
	           --python_out=. \
	           felixbackend.proto

.PHONEY: force
force:
	true
bin/calico-felix: force felix/proto/felixbackend.pb.go
	mkdir -p bin
	go build -o "$@" "./felix/felix.go"

bin/calicoctl: force
	mkdir -p bin
	go build -o "$@" "./calicoctl/calicoctl.go"

release/calicoctl: force
	mkdir -p release
	cd build-calicoctl && docker build -t calicoctl-build .
	docker run --rm -v `pwd`:/libcalico-go calicoctl-build /libcalico-go/build-calicoctl/build.sh

# Build calicoctl in a container.
build-containerized: $(BUILD_CONTAINER_MARKER)
	docker run -ti --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/tigera/libcalico-go:rw \
	$(BUILD_CONTAINER_NAME) make bin/calicoctl

# Run the tests in a container. Useful for CI, Mac dev.
.PHONY: test-containerized
test-containerized: $(BUILD_CONTAINER_MARKER)
	docker run -ti --rm --privileged --net=host \
	-e PLUGIN=calico \
	-v ${PWD}:/go/src/github.com/tigera/libcalico-go:rw \
	$(BUILD_CONTAINER_NAME) make ut

$(BUILD_CONTAINER_MARKER): Dockerfile.build
	docker build -f Dockerfile.build -t $(BUILD_CONTAINER_NAME) .
	touch $@

# Etcd is used by the tests
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd quay.io/coreos/etcd:v2.3.6 \
	--advertise-client-urls "http://127.0.0.1:2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

clean:
	rm -rf bin
	rm -f felix/proto/felixbackend.pb.go
