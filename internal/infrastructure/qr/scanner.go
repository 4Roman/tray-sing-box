// Package qr finds and decodes a QR code on the user's screen(s).
package qr

import (
	"fmt"
	"image"

	"github.com/kbinani/screenshot"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// ScanScreen captures every display and returns the text of the first QR code
// found. Displays are scanned in order; the first hit wins.
func ScanScreen() (string, error) {
	displays := screenshot.NumActiveDisplays()
	if displays == 0 {
		return "", fmt.Errorf("no active displays found")
	}

	var lastErr error
	for i := 0; i < displays; i++ {
		img, err := screenshot.CaptureRect(screenshot.GetDisplayBounds(i))
		if err != nil {
			lastErr = fmt.Errorf("failed to capture display %d: %w", i, err)
			continue
		}

		text, err := Decode(img)
		if err == nil {
			return text, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no QR code found")
	}
	return "", fmt.Errorf("no QR code found on screen: %w", lastErr)
}

// Decode extracts QR code text from an image
func Decode(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("failed to prepare image: %w", err)
	}

	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, map[gozxing.DecodeHintType]any{
		gozxing.DecodeHintType_TRY_HARDER: true,
	})
	if err != nil {
		return "", fmt.Errorf("QR decode failed: %w", err)
	}

	return result.GetText(), nil
}
