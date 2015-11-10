help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  ut         to run the unit tests inside Docker"
	@echo "  docs       to build the docs in HTML"

ut:
	docker build -t calico/ut -f utils/calico-uts.Dockerfile .
	docker run -t calico/ut

docs:
	docker build -t calico/docs -f utils/calico-docs.Dockerfile .
	docker run -v $(CURDIR):/calico -t calico/docs
