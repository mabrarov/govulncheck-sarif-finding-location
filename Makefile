# https://clarkgrubb.com/makefile-style-guide
MAKEFLAGS     += --warn-undefined-variables
SHELL         := bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.SUFFIXES:

GO              ?= go
GOFUMPT         ?= gofumpt
GOFUMPT_VERSION ?= v0.9.2
MAKEFILE_DIR    := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
PREFIX          ?= $(MAKEFILE_DIR)/.build
BINNAME         ?= govulncheck-sarif-finding-location

# https://tensin.name/blog/makefile-escaping.html
define noexpand
    ifeq ($$(origin $(1)),environment)
        $(1) := $$(value $(1))
    else ifeq ($$(origin $(1)),environment override)
        $(1) := $$(value $(1))
    else ifeq ($$(origin $(1)),command line)
        override $(1) := $$(value $(1))
    endif
endef

$(eval $(call noexpand,GO))
$(eval $(call noexpand,GOFUMPT))
$(eval $(call noexpand,GOFUMPT_VERSION))
$(eval $(call noexpand,PREFIX))
$(eval $(call noexpand,BINNAME))

escape = $(subst ','\'',$(1))
squote = '$(call escape,$(1))'

OUTPUT := $(PREFIX)/$(BINNAME)$(shell $(call squote,$(GO)) env GOEXE)

.PHONY: all
all: format test build

.PHONY: format-deps
format-deps:
	$(call squote,$(GO)) install mvdan.cc/gofumpt@$(call squote,$(GOFUMPT_VERSION))

.PHONY: format
format: format-deps
	cd $(call squote,$(MAKEFILE_DIR)) && $(call squote,$(GOFUMPT)) -l -w .

.PHONY: test
test:
	$(call squote,$(GO)) test -C $(call squote,$(MAKEFILE_DIR)) -count 1 -cover ./...

.PHONY: build
build:
	CGO_ENABLED=0 $(call squote,$(GO)) build -C $(call squote,$(MAKEFILE_DIR)) -trimpath -o $(call squote,$(OUTPUT)) .

.PHONY: clean
clean:
	$(RM) $(call squote,$(OUTPUT))
