package tritrpcv1

import "fmt"

func TritPack243(trits []byte) []byte {
	out := make([]byte, 0, (len(trits)/5)+3)
	i := 0
	for i+5 <= len(trits) {
		val := 0
		for _, t := range trits[i : i+5] {
			if t > 2 {
				panic("invalid trit")
			}
			val = val*3 + int(t)
		}
		out = append(out, byte(val))
		i += 5
	}
	k := len(trits) - i
	if k > 0 {
		out = append(out, byte(243+(k-1)))
		val := 0
		for _, t := range trits[i:] {
			val = val*3 + int(t)
		}
		out = append(out, byte(val))
	}
	return out
}

func TritUnpack243(bytes []byte) ([]byte, error) {
	var trits []byte
	i := 0
	for i < len(bytes) {
		b := bytes[i]
		i++
		if b <= 242 {
			val := int(b)
			group := make([]byte, 5)
			for j := 4; j >= 0; j-- {
				group[j] = byte(val % 3)
				val /= 3
			}
			trits = append(trits, group...)
		} else if b >= 243 && b <= 246 {
			if i >= len(bytes) {
				return nil, fmt.Errorf("truncated tail")
			}
			k := int(b - 243 + 1)
			val := int(bytes[i])
			i++
			group := make([]byte, k)
			for j := k - 1; j >= 0; j-- {
				group[j] = byte(val % 3)
				val /= 3
			}
			trits = append(trits, group...)
		} else {
			return nil, fmt.Errorf("invalid byte 247..255")
		}
	}
	return trits, nil
}
