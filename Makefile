# Run from WSL. The app is Windows-only, so the build uses the Windows Go
# toolchain via WSL interop; override GO/GO_WINRES if your paths differ.
GO        ?= /mnt/c/Users/user/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.3.windows-amd64/bin/go.exe
GO_WINRES ?= /mnt/c/Users/user/go/bin/go-winres.exe

EXE := bin/tray-sing-box.exe
ICO := assets/icons/tray.ico

.PHONY: all build icons test clean

all: build

# Build the exe, then patch Windows resources (icon, admin manifest, version
# info) into it with `go-winres patch` — no .syso juggling needed.
build: $(ICO) $(GO_WINRES)
	$(GO) build -ldflags="-H windowsgui" -o $(EXE) .
	$(GO_WINRES) patch --in build/winres/winres.json --no-backup $(EXE)
	mkdir -p bin/assets/icons
	cp $(ICO) bin/assets/icons/

icons: $(ICO)

$(ICO): assets/icons/tray.svg tools/genicons/main.go
	$(GO) run ./tools/genicons

$(GO_WINRES):
	$(GO) install github.com/tc-hib/go-winres@latest

test:
	$(GO) test -short ./...

clean:
	rm -f $(EXE) $(ICO) bin/assets/icons/tray.ico
