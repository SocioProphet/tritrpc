package tritrpcv1

// Minimal Path-B decoders for strings and union index (subset used in fixtures)
func PBDecodeLen(buf []byte, off int) (int, int) {
	// TLEB3 decode for length: reuse TLEB3 decoder by repacking; here we assume small inputs and just reuse TritUnpack on a byte-by-byte basis
	// NOTE: For production, implement a proper scanner.
	trits := []byte{}
	start := off
	for {
		b := buf[off]
		off++
		ts, _ := TritUnpack243([]byte{b})
		trits = append(trits, ts...)
		if len(trits) >= 3 {
			v := uint64(0)
			used := 0
			for j := 0; j < len(trits)/3; j++ {
				c, p1, p0 := trits[3*j], trits[3*j+1], trits[3*j+2]
				digit := uint64(p1)*3 + uint64(p0)
				mul := uint64(1)
				for k := 0; k < j; k++ {
					mul *= 9
				}
				v += digit * mul
				if c == 0 {
					used = (j + 1) * 3
					break
				}
			}
			if used > 0 {
				pack := TritPack243(trits[:used])
				usedBytes := len(pack)
				newOff := start + usedBytes
				return int(v), newOff
			}
		}
	}
}

func PBDecodeString(buf []byte, off int) (string, int) {
	l, o2 := PBDecodeLen(buf, off)
	s := string(buf[o2 : o2+l])
	return s, o2 + l
}

func PBDecodeUnionIndex(buf []byte, off int) (int, int) {
	l, o2 := PBDecodeLen(buf, off)
	return l, o2
}
