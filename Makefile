# Run from WSL. The app is Windows-only, so the build uses the Windows Go
# toolchain via WSL interop; override GO/GO_WINRES if your paths differ.
WINUSER   ?= $(shell cmd.exe /c "echo %USERNAME%" 2>/dev/null | tr -d '\r')
GO        ?= /mnt/c/Users/$(WINUSER)/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.windows-amd64/bin/go.exe
GO_WINRES ?= /mnt/c/Users/$(WINUSER)/go/bin/go-winres.exe

EXE     := bin/tray-sing-box.exe
ICO     := assets/icons/tray.ico
ICO_OFF := assets/icons/tray-off.ico

# Stamped into the exe (`tray-sing-box.exe --version`, first lines of the log)
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -H windowsgui -X tray-sing-box/internal/config.Version=$(VERSION)

.PHONY: all build icons test clean

all: build

# Build the exe, then patch Windows resources (icon, admin manifest, version
# info) into it with `go-winres patch` — no .syso juggling needed. The tray
# icons are embedded (package assets), so they must exist BEFORE go build:
# the exe is the whole app, nothing has to be copied next to it.
build: $(ICO) $(GO_WINRES)
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(EXE) .
	$(GO_WINRES) patch --in build/winres/winres.json --no-backup $(EXE)

icons: $(ICO)

# genicons writes both ICOs in one run; tray.ico stands in for the pair
$(ICO): assets/icons/tray.svg tools/genicons/main.go
	$(GO) run ./tools/genicons

$(GO_WINRES):
	$(GO) install github.com/tc-hib/go-winres@v0.3.3

test:
	$(GO) test -short ./...

clean:
	rm -f $(EXE) $(ICO) $(ICO_OFF)
