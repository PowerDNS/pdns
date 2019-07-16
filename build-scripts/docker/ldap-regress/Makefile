NAME = powerdns/ldap-regress
VERSION = 1.2.4
REVISION = 0

.PHONY: all build build-nocache dep

all: build

dep:
	mkdir -p bootstrap/schema
	cp ../../../modules/ldapbackend/*.schema bootstrap/schema

build: dep
	docker build --build-arg VERSION=$(VERSION) -t $(NAME):$(VERSION)-$(REVISION) --rm .

build-nocache: dep
	docker build --build-arg VERSION=$(VERSION) -t $(NAME):$(VERSION)-$(REVISION) --no-cache --rm .

push: build
	docker push powerdns/ldap-regress:$(VERSION)-$(REVISION)