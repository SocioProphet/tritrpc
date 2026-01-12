package tritrpcv1

import "testing"

func TestMicroVectors(t *testing.T) {
	b := TritPack243([]byte{2, 1, 0, 0, 2})
	if len(b) != 1 || b[0] != 0xBF {
		t.Fatalf("pack fail, got %x", b)
	}
	b2 := TritPack243([]byte{2, 2, 1})
	if len(b2) != 2 || b2[0] != 0xF5 || b2[1] != 0x19 {
		t.Fatalf("tail fail, got %x", b2)
	}
}

func TestTleb3EncodeLen(t *testing.T) {
	for _, n := range []uint64{0, 1, 2, 3, 8, 9, 10, 123, 4096, 65535} {
		enc := TLEB3EncodeLen(n)
		if len(enc) == 0 {
			t.Fatalf("empty encoding for %d", n)
		}
	}
}
