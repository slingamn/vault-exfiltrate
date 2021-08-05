# Sets the build version based on the output of the following command, if we are building for a tag, that's the build else it uses the current git branch as the build
# BUILD_VERSION:=$(shell git describe --exact-match --tags $(git log -n1 --pretty='%h') 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null)
# CURRENT_BRANCH=$(shell git rev-parse --abbrev-ref HEAD 2>/dev/null)
CURRENT_BRANCH=$(if $(REF_BRANCH), $(REF_BRANCH), $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null))
CURRENT_TIMESTAMP=$(shell date +"%Y_%m_%d_%H_%M_%S" 2>/dev/null)
BUILD_VERSION:=$(shell git describe --exact-match --tags $(git log -n1 --pretty='%h') 2>/dev/null ||  echo $(CURRENT_BRANCH)_$(CURRENT_TIMESTAMP))
BUILD_TIME:=$(shell date 2>/dev/null)
default: linux

.PHONY: linux
linux:
	@echo "Building vault_exfiltrate(vault_exfiltrate) binary to './builds/vault_exfiltrate'"
	@(cd cmd/; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build --ldflags "-s -w -X 'main.BuildVersion=${BUILD_VERSION}'" -o ../builds/vault_exfiltrate)

.PHONY: vault_exfiltrate_osx
osx:
	@echo "Building vault-exfiltrate(vault_exfiltrate_osx) binary to './builds/vault_exfiltrate_osx'"
	@(cd cmd/; CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build --ldflags "-s -w -X 'main.BuildVersion=${BUILD_VERSION}'" -o ../builds/vault_exfiltrate_osx)

.PHONY: vault_exfiltrate_windows
windows:
	@echo "Building vault-exfiltrate(vault_exfiltrate_windows) binary to './builds/vault_exfiltrate_windows.exe'"
	@(cd cmd/; CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build --ldflags "-s -w -X 'main.BuildVersion=${BUILD_VERSION}'" -o ../builds/vault_exfiltrate_windows.exe)

clean:
	@echo "Cleaning up all the generated files"
	@find . -name '*.test' | xargs rm -fv
	@find . -name '*~' | xargs rm -fv
	@rm -rvf vault_exfiltrate_windows.exe vault_exfiltrate_osx vault_exfiltrate
 
