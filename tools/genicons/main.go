// genicons renders assets/icons/tray.svg into assets/icons/tray.ico and a
// desaturated assets/icons/tray-off.ico (tray icon for the "VPN stopped"
// state). Run from the repo root (make build does): go run ./tools/genicons
//
// Windows cannot consume SVG directly: the tray icon goes through
// LoadImageW(IMAGE_ICON, LR_LOADFROMFILE) and the exe icon is embedded by
// go-winres — both want ICO. So the SVG is the editable source of truth and
// this tool produces the ICO artifacts used by both pipelines.
//
// ICO layout: 16/32/48 px entries are stored as uncompressed 32-bit BMP
// (LoadImageW-safe on every Windows version), 256 px as PNG (supported since
// Vista, keeps the file small).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"log"
	"os"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
)

const (
	svgPath    = "assets/icons/tray.svg"
	icoPath    = "assets/icons/tray.ico"
	icoOffPath = "assets/icons/tray-off.ico"
)

var bmpSizes = []int{16, 32, 48}
var pngSizes = []int{256}

func main() {
	icon, err := oksvg.ReadIcon(svgPath, oksvg.StrictErrorMode)
	if err != nil {
		log.Fatalf("parse %s: %v", svgPath, err)
	}

	writeICO(icoPath, icon, nil)
	writeICO(icoOffPath, icon, desaturate)
}

// writeICO renders the SVG at every size, optionally post-processing each
// raster with transform, and packs the results into one ICO file.
func writeICO(path string, icon *oksvg.SvgIcon, transform func(*image.RGBA)) {
	rendered := func(size int) *image.RGBA {
		img := render(icon, size)
		if transform != nil {
			transform(img)
		}
		return img
	}

	type entry struct {
		size int
		data []byte
	}
	var entries []entry
	for _, s := range bmpSizes {
		entries = append(entries, entry{s, encodeBMP(rendered(s))})
	}
	for _, s := range pngSizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, rendered(s)); err != nil {
			log.Fatalf("png encode %dpx: %v", s, err)
		}
		entries = append(entries, entry{s, buf.Bytes()})
	}

	var ico bytes.Buffer
	// ICONDIR
	binary.Write(&ico, binary.LittleEndian, [3]uint16{0, 1, uint16(len(entries))})
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		wh := byte(e.size) // 256 wraps to 0, which is how ICO encodes 256
		binary.Write(&ico, binary.LittleEndian, struct {
			W, H, Colors, Rsv byte
			Planes, BPP       uint16
			Size, Offset      uint32
		}{wh, wh, 0, 0, 1, 32, uint32(len(e.data)), uint32(offset)})
		offset += len(e.data)
	}
	for _, e := range entries {
		ico.Write(e.data)
	}

	if err := os.WriteFile(path, ico.Bytes(), 0644); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%d bytes, sizes %v+%v)\n", path, ico.Len(), bmpSizes, pngSizes)
}

// desaturate converts the image to grayscale (Rec. 601 luma, alpha kept) —
// the "VPN stopped" tray icon is a dimmed version of the normal one.
func desaturate(img *image.RGBA) {
	for i := 0; i < len(img.Pix); i += 4 {
		r, g, b := int(img.Pix[i]), int(img.Pix[i+1]), int(img.Pix[i+2])
		y := byte((299*r + 587*g + 114*b) / 1000)
		img.Pix[i], img.Pix[i+1], img.Pix[i+2] = y, y, y
	}
}

func render(icon *oksvg.SvgIcon, size int) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	icon.SetTarget(0, 0, float64(size), float64(size))
	scanner := rasterx.NewScannerGV(size, size, img, img.Bounds())
	icon.Draw(rasterx.NewDasher(size, size, scanner), 1.0)
	return img
}

// encodeBMP produces an ICO-embedded DIB: BITMAPINFOHEADER with doubled
// height, bottom-up BGRA pixels, then the 1-bpp AND mask derived from alpha.
func encodeBMP(img *image.RGBA) []byte {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	maskStride := ((w + 31) / 32) * 4
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, struct {
		HeaderSize    uint32
		Width, Height int32
		Planes, BPP   uint16
		Compression   uint32
		ImageSize     uint32
		XPPM, YPPM    int32
		ClrUsed, Imp  uint32
	}{40, int32(w), int32(2 * h), 1, 32, 0, uint32(h * (w*4 + maskStride)), 0, 0, 0, 0})

	for y := h - 1; y >= 0; y-- { // XOR map, bottom-up
		for x := 0; x < w; x++ {
			r, g, b, a := rgbaAt(img, x, y)
			buf.Write([]byte{b, g, r, a})
		}
	}
	for y := h - 1; y >= 0; y-- { // AND mask: bit set = transparent
		row := make([]byte, maskStride)
		for x := 0; x < w; x++ {
			if _, _, _, a := rgbaAt(img, x, y); a < 128 {
				row[x/8] |= 0x80 >> (x % 8)
			}
		}
		buf.Write(row)
	}
	return buf.Bytes()
}

func rgbaAt(img *image.RGBA, x, y int) (r, g, b, a byte) {
	i := img.PixOffset(x, y)
	return img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3]
}
