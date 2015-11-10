help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  ut         to run the unit tests inside Docker"
	@echo "  docs       build the docs in HTML"

ut: calicout.created
        docker build -t calico/ut -f utils/calico-ut.Dockerfile .
	docker run -t calico/ut

docs: calicodocs.created
	docker build -t calico/docs -f utils/calico-docs.Dockerfile .
	docker run -v $(CURDIR):/calico -t calico/docs
