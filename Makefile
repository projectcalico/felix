all: pyinstaller

.PHONY: update-vendor
update-vendor:
	cd go && glide up

go/felix/proto/felixbackend.pb.go: go/felix/proto/felixbackend.proto
	docker run -ti \
	           -v $${PWD}/go/felix/proto:/src:rw \
	           --rm \
	           calico/protoc \
	           --gogofaster_out=. \
	           felixbackend.proto

calico/felix/felixbackend_pb2.py: go/felix/proto/felixbackend.proto
	docker run -ti \
	           -v $${PWD}/go/felix/proto:/src:rw \
	           -v $${PWD}/calico/felix/:/dst:rw \
	           --rm \
	           calico/protoc \
	           --python_out=/dst/ \
	           felixbackend.proto

.PHONY: bin/calico-felix
bin/calico-felix: go/felix/proto/felixbackend.pb.go
	mkdir -p bin
	go build -o "$@" "./go/felix/felix.go"

.PHONY: pyinstaller
pyinstaller: bin/calico-felix calico/felix/felixbackend_pb2.py
	./build-pyi-bundle.sh

.PHONY: clean
clean:
	rm -rf bin dist calico/felix/felixbackend_pb2.py go/felix/proto/felixbackend.pb.go
