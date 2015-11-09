help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  ut         to run the unit tests inside Docker"
	@echo "  docs       build the docs in HTML"

calicout.created:
	docker build -t calico/ut -f utils/calico-uts.Dockerfile .
	touch calicout.created

ut: calicout.created
	docker run -v $(CURDIR):/calico -t calico/ut

calicodocs.created:
	docker build -t calico/docs -f utils/calico-docs.Dockerfile .

docs: calicodocs.created
	docker run -v $(CURDIR):/calico -t calico/docs
