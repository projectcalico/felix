help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  calicout.created   to rebuild the calico/ut Docker image"
	@echo "  ut                 to run the unit tests inside Docker"

calicout.created:
	docker build -t calico/ut -f utils/calico-uts.Dockerfile .
	touch calicout.created

ut: calicout.created
	docker run -v $(CURDIR):/calico -t calico/ut
