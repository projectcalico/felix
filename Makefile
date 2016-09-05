all: pyinstaller

DEB_VERSION:=$(shell grep calico debian/changelog | \
                     head -n 1 | cut -d '(' -f 2 | cut -d ')' -f 1 | \
                     cut -d '-' -f 1)
GO_FILES:=$(shell find go/ -type f -name '*.go')
PY_FILES:=*.py calico/felix/felixbackend_pb2.py $(shell find calico/ docs/  -type f -name '*.py')

.PHONY: deb
deb: dist/calico-felix/calico-felix
	rm -rf dist/deb
	mkdir -p dist/deb/calico-$(DEB_VERSION)
	cp -r dist/calico-felix dist/deb/calico-$(DEB_VERSION)/pyi
	cp -r etc \
	      utils \
	      calico \
	      setup.py \
	      *requirements.txt \
	      LICENSE \
	      MANIFEST.in \
	      README.md \
	      dist/deb/calico-$(DEB_VERSION)
	cd dist/deb && tar -czf calico_$(DEB_VERSION).orig.tar.gz calico-$(DEB_VERSION)
	cp -r debian dist/deb/calico-$(DEB_VERSION)
	cd dist/deb/calico-$(DEB_VERSION) && debuild -us -uc

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
