package oscore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"os"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/ccm"
)

func newCCM(t testing.TB, key []byte, tagSize, nonceSize int) cipher.AEAD {
	t.Helper()
	b, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ccm.NewCCM(b, tagSize, nonceSize)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

// The packet vectors of RFC 3610, Section 8. They use a 13-byte nonce with 8-
// and 10-byte tags.
func TestCCMRFC3610(t *testing.T) {
	var vectors []struct {
		Vector     int
		Key        string
		Nonce      string
		AAD        string
		Plaintext  string
		Ciphertext string
		TagSize    int
	}
	readJSON(t, "testdata/rfc3610.json", &vectors)
	if len(vectors) != 24 {
		t.Fatalf("got %d vectors, want 24", len(vectors))
	}
	for _, v := range vectors {
		a := newCCM(t, unhex(t, v.Key), v.TagSize, 13)
		nonce, aad, pt, ct := unhex(t, v.Nonce), unhex(t, v.AAD), unhex(t, v.Plaintext), unhex(t, v.Ciphertext)
		if got := a.Seal(nil, nonce, pt, aad); !bytes.Equal(got, ct) {
			t.Errorf("vector %d: Seal = %x, want %x", v.Vector, got, ct)
		}
		if got, err := a.Open(nil, nonce, ct, aad); err != nil || !bytes.Equal(got, pt) {
			t.Errorf("vector %d: Open = %x, %v", v.Vector, got, err)
		}
	}
}

func TestWycheproofCCM(t *testing.T) {
	var file struct {
		NumberOfTests int
		TestGroups    []struct {
			IvSize, KeySize, TagSize int
			Tests                    []struct {
				TcID                       int
				Comment                    string
				Key, Iv, Aad, Msg, Ct, Tag string
				Result                     string
			}
		}
	}
	readJSON(t, "testdata/aes_ccm_test.json", &file)
	ran := 0
	for _, g := range file.TestGroups {
		for _, tc := range g.Tests {
			ran++
			b, err := aes.NewCipher(unhex(t, tc.Key))
			if err != nil {
				t.Fatalf("test %d: %v", tc.TcID, err)
			}
			a, err := ccm.NewCCM(b, g.TagSize/8, g.IvSize/8)
			if err != nil {
				if tc.Result == "valid" {
					t.Errorf("test %d (%s): NewCCM: %v", tc.TcID, tc.Comment, err)
				}
				continue
			}
			nonce, aad, msg := unhex(t, tc.Iv), unhex(t, tc.Aad), unhex(t, tc.Msg)
			sealed := append(unhex(t, tc.Ct), unhex(t, tc.Tag)...)
			got, err := a.Open(nil, nonce, sealed, aad)
			switch tc.Result {
			case "valid":
				if err != nil || !bytes.Equal(got, msg) {
					t.Errorf("test %d (%s): Open = %x, %v", tc.TcID, tc.Comment, got, err)
				}
				if s := a.Seal(nil, nonce, msg, aad); !bytes.Equal(s, sealed) {
					t.Errorf("test %d (%s): Seal = %x, want %x", tc.TcID, tc.Comment, s, sealed)
				}
			case "invalid":
				if err == nil {
					t.Errorf("test %d (%s): Open succeeded on an invalid input", tc.TcID, tc.Comment)
				}
			}
		}
	}
	if ran != file.NumberOfTests {
		t.Fatalf("ran %d tests, file has %d", ran, file.NumberOfTests)
	}
}

func TestCCMRejectsBadSizes(t *testing.T) {
	b, _ := aes.NewCipher(make([]byte, 16))
	for _, tagSize := range []int{0, 2, 3, 5, 17, 18} {
		if _, err := ccm.NewCCM(b, tagSize, 13); err == nil {
			t.Errorf("NewCCM accepted tag size %d", tagSize)
		}
	}
	for _, nonceSize := range []int{0, 6, 14, 16} {
		if _, err := ccm.NewCCM(b, 8, nonceSize); err == nil {
			t.Errorf("NewCCM accepted nonce size %d", nonceSize)
		}
	}
}

func TestCCMInPlace(t *testing.T) {
	a := newCCM(t, make([]byte, 16), 8, 13)
	nonce, aad := make([]byte, 13), []byte("aad")
	msg := []byte("in-place plaintext")
	buf := make([]byte, len(msg), len(msg)+a.Overhead())
	copy(buf, msg)
	sealed := a.Seal(buf[:0], nonce, buf, aad)
	if want := a.Seal(nil, nonce, msg, aad); !bytes.Equal(sealed, want) {
		t.Fatalf("in-place Seal = %x, want %x", sealed, want)
	}
	opened, err := a.Open(sealed[:0], nonce, sealed, aad)
	if err != nil || !bytes.Equal(opened, msg) {
		t.Fatalf("in-place Open = %q, %v", opened, err)
	}
}

func TestCCMOpenRejectsTampering(t *testing.T) {
	a := newCCM(t, make([]byte, 16), 8, 13)
	nonce, aad := make([]byte, 13), []byte{1, 2, 3}
	sealed := a.Seal(nil, nonce, []byte("message_3 plaintext"), aad)
	for i := range sealed {
		for _, bit := range []byte{0x01, 0x80} {
			c := bytes.Clone(sealed)
			c[i] ^= bit
			if _, err := a.Open(nil, nonce, c, aad); err == nil {
				t.Fatalf("Open accepted a ciphertext with byte %d changed", i)
			}
		}
	}
	if _, err := a.Open(nil, nonce, sealed, []byte{1, 2, 4}); err == nil {
		t.Fatal("Open accepted different additional data")
	}
	if _, err := a.Open(nil, nonce, sealed[:len(sealed)-1], aad); err == nil {
		t.Fatal("Open accepted a truncated ciphertext")
	}
	if _, err := a.Open(nil, nonce, sealed[:7], aad); err == nil {
		t.Fatal("Open accepted a ciphertext shorter than the tag")
	}
}

func TestCCMOpenClearsOutputOnFailure(t *testing.T) {
	a := newCCM(t, make([]byte, 16), 8, 13)
	nonce := make([]byte, 13)
	sealed := a.Seal(nil, nonce, []byte("secret"), nil)
	sealed[0] ^= 1
	dst := make([]byte, 0, 16)
	if _, err := a.Open(dst, nonce, sealed, nil); err == nil {
		t.Fatal("Open accepted a tampered ciphertext")
	}
	if !bytes.Equal(dst[:6], make([]byte, 6)) {
		t.Fatalf("Open left %x in dst after failing", dst[:6])
	}
}

func TestCCMLongAdditionalData(t *testing.T) {
	// Lengths of 0xff00 and above use the six-byte length encoding.
	a := newCCM(t, make([]byte, 16), 16, 13)
	nonce := make([]byte, 13)
	for _, v := range []struct {
		n      int
		sealed string
	}{
		{0xfeff, "adc78e97e69e0ee0a7796a48a044feba50"},
		{0xff00, "ad5e2b71e62f7b5c7347a86cf49422af62"},
		{0x10000, "ad26e4d860f3161fa77f750dea4f1cf3d3"},
	} {
		aad := bytes.Repeat([]byte{0xa5}, v.n)
		sealed := a.Seal(nil, nonce, []byte("x"), aad)
		if want := unhex(t, v.sealed); !bytes.Equal(sealed, want) {
			t.Errorf("additional data of %d bytes: Seal = %x, want %x", v.n, sealed, want)
		}
		if _, err := a.Open(nil, nonce, sealed, aad); err != nil {
			t.Errorf("additional data of %d bytes: %v", v.n, err)
		}
	}
}

func TestCCMSealPanicsOnLongMessage(t *testing.T) {
	a := newCCM(t, make([]byte, 16), 8, 13)
	defer func() {
		if recover() == nil {
			t.Fatal("Seal accepted a 65536-byte message with a 2-byte length field")
		}
	}()
	a.Seal(nil, make([]byte, 13), make([]byte, 1<<16), nil)
}

func FuzzCCMRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), []byte("aad"), uint8(8), uint8(13))
	f.Fuzz(func(t *testing.T, msg, aad []byte, tagSize, nonceSize uint8) {
		b, _ := aes.NewCipher(make([]byte, 16))
		a, err := ccm.NewCCM(b, int(tagSize), int(nonceSize))
		if err != nil {
			return
		}
		if len(msg) >= 1<<16 {
			return
		}
		nonce := make([]byte, a.NonceSize())
		sealed := a.Seal(nil, nonce, msg, aad)
		if len(sealed) != len(msg)+a.Overhead() {
			t.Fatalf("sealed length %d, want %d", len(sealed), len(msg)+a.Overhead())
		}
		got, err := a.Open(nil, nonce, sealed, aad)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("Open = %x, %v", got, err)
		}
	})
}
