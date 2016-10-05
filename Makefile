# Copyright (c) 2016 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all
all: felix-docker-image

.PHONY: update-tools
update-tools:

.PHONY: ut
ut:
	./run-unit-test.sh

dist/calico-felix/calico-felix:
	./build-pyi-bundle.sh
	# PyInstaller doesn't update mtime as Make expects, check the file was
	# really build then touch it.
	[ -e dist/calico-felix/calico-felix ] && touch dist/calico-felix/calico-felix

# Placeholder make target to match the one that is upcoming on the
# golang felix branch so that the CI can build either branch.
.PHONY: felix-docker-image
felix-docker-image: dist/calico-felix/calico-felix
	docker build -t calico/felix .

.PHONY: clean
clean:
	rm -rf dist bin
