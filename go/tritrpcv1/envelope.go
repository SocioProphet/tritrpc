package tritrpcv1

import (
	"golang.org/x/crypto/chacha20poly1305"
)

var SCHEMA_ID_BYTES = []byte{178, 171, 129, 69, 136, 249, 156, 135, 93, 55, 187, 117, 70, 208, 223, 67, 105, 194, 139, 197, 246, 12, 227, 138, 102, 7, 218, 196, 104, 3, 67, 82}
var CONTEXT_ID_BYTES = []byte{230, 87, 44, 14, 97, 143, 24, 213, 114, 212, 194, 150, 157, 180, 144, 150, 89, 240, 158, 174, 243, 46, 198, 111, 187, 128, 75, 173, 157, 137, 170, 205}
var MAGIC_B2 = []byte{0xF3, 0x2A}
var SCHEMA_ID_32 = []byte{0xb2, 0xab, 0x81, 0x45, 0x88, 0xf9, 0x9c, 0x87, 0x5d, 0x37, 0xbb, 0x75, 0x46, 0xd0, 0xdf, 0x43, 0x69, 0xc2, 0x8b, 0xc5, 0xf6, 0x0c, 0xe3, 0x8a, 0x66, 0x07, 0xda, 0xc4, 0x68, 0x03, 0x43, 0x52}
var CONTEXT_ID_32 = []byte{0xe6, 0x57, 0x2c, 0x0e, 0x61, 0x8f, 0x18, 0xd5, 0x72, 0xd4, 0xc2, 0x96, 0x9d, 0xb4, 0x90, 0x96, 0x59, 0xf0, 0x9e, 0xae, 0xf3, 0x2e, 0xc6, 0x6f, 0xbb, 0x80, 0x4b, 0xad, 0x9d, 0x89, 0xaa, 0xcd}

func flagsTrits(aead bool, compress bool) []byte {
	var a, c byte
	if aead {
		a = 2
	}
	if compress {
		c = 2
	}
	return []byte{a, c, 0}
}

func lenPrefix(b []byte) []byte {
	return TLEB3EncodeLen(uint64(len(b)))
}

func BuildEnvelope(service, method string, payload []byte, aux []byte, aeadTag []byte, aeadOn bool, compress bool) []byte {
	out := make([]byte, 0)
	out = append(out, lenPrefix(MAGIC_B2)...)
	out = append(out, MAGIC_B2...)

	ver := TritPack243([]byte{1})
	out = append(out, lenPrefix(ver)...)
	out = append(out, ver...)

	mode := TritPack243([]byte{0})
	out = append(out, lenPrefix(mode)...)
	out = append(out, mode...)

	flags := TritPack243(flagsTrits(aeadOn, compress))
	out = append(out, lenPrefix(flags)...)
	out = append(out, flags...)

	schema := SCHEMA_ID_32
	context := CONTEXT_ID_32
	out = append(out, lenPrefix(schema)...)
	out = append(out, schema...)
	out = append(out, lenPrefix(context)...)
	out = append(out, context...)

	svc := []byte(service)
	out = append(out, lenPrefix(svc)...)
	out = append(out, svc...)

	m := []byte(method)
	out = append(out, lenPrefix(m)...)
	out = append(out, m...)

	out = append(out, lenPrefix(payload)...)
	out = append(out, payload...)

	if aux != nil {
		out = append(out, lenPrefix(aux)...)
		out = append(out, aux...)
	}
	if aeadTag != nil {
		out = append(out, lenPrefix(aeadTag)...)
		out = append(out, aeadTag...)
	}

	return out
}

func EnvelopeWithTag(service, method string, payload, aux []byte, key [32]byte, nonce [24]byte) ([]byte, []byte, error) {
	aad := BuildEnvelope(service, method, payload, aux, nil, true, false)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, nil, err
	}
	ct := aead.Seal(nil, nonce[:], []byte{}, aad)
	tag := ct[len(ct)-16:]
	frame := BuildEnvelope(service, method, payload, aux, tag, true, false)
	return frame, tag, nil
}
