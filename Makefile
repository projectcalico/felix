help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  calico/ut    to rebuild the calico/ut Docker image"
	@echo "  ut           to run the unit tests inside Docker"

calico/ut:
	docker build -t calico/ut -f utils/calico-uts.Dockerfile

ut:
	docker run -v $(CURDIR):/calico -t calico/ut
