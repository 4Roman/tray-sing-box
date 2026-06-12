package qr

import (
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func TestDecodeRoundTrip(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?security=reality&pbk=KEY#node"

	writer := qrcode.NewQRCodeWriter()
	matrix, err := writer.Encode(link, gozxing.BarcodeFormat_QR_CODE, 256, 256, nil)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	got, err := Decode(matrix)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != link {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, link)
	}
}
