package tritrpcv1

import (
	"errors"
)

type Envelope struct {
	Magic    []byte
	Version  []byte
	Mode     []byte
	Flags    []byte
	Schema   []byte
	Context  []byte
	Service  string
	Method   string
	Payload  []byte
	Aux      []byte
	Tag      []byte
	AeadOn   bool
	Compress bool
	TagStart int
}

func DecodeEnvelope(frame []byte) (*Envelope, error) {
	off := 0
	readField := func() ([]byte, int, int, error) {
		l, no, err := TLEB3DecodeLen(frame, off)
		if err != nil {
			return nil, 0, 0, err
		}
		valStart := no
		valEnd := valStart + int(l)
		if valEnd > len(frame) {
			return nil, 0, 0, errors.New("field length exceeds frame")
		}
		start := off
		off = valEnd
		return frame[valStart:valEnd], valEnd, start, nil
	}

	magic, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	version, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	mode, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	flags, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	schema, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	context, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	svcBytes, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	methodBytes, _, _, err := readField()
	if err != nil {
		return nil, err
	}
	payload, _, _, err := readField()
	if err != nil {
		return nil, err
	}

	trits, _ := TritUnpack243(flags)
	aeadOn := len(trits) > 0 && trits[0] == 2
	compress := len(trits) > 1 && trits[1] == 2

	var aux []byte
	var tag []byte
	tagStart := -1

	if off < len(frame) {
		if aeadOn {
			field, _, start, err := readField()
			if err != nil {
				return nil, err
			}
			if off < len(frame) {
				tagField, _, tagFieldStart, err := readField()
				if err != nil {
					return nil, err
				}
				aux = append([]byte{}, field...)
				tag = append([]byte{}, tagField...)
				tagStart = tagFieldStart
			} else {
				tag = append([]byte{}, field...)
				tagStart = start
			}
		} else {
			field, _, _, err := readField()
			if err != nil {
				return nil, err
			}
			aux = append([]byte{}, field...)
		}
	}

	if off != len(frame) {
		return nil, errors.New("extra bytes after envelope parsing")
	}

	return &Envelope{
		Magic:    append([]byte{}, magic...),
		Version:  append([]byte{}, version...),
		Mode:     append([]byte{}, mode...),
		Flags:    append([]byte{}, flags...),
		Schema:   append([]byte{}, schema...),
		Context:  append([]byte{}, context...),
		Service:  string(svcBytes),
		Method:   string(methodBytes),
		Payload:  append([]byte{}, payload...),
		Aux:      aux,
		Tag:      tag,
		AeadOn:   aeadOn,
		Compress: compress,
		TagStart: tagStart,
	}, nil
}

func AADBeforeTag(frame []byte, env *Envelope) ([]byte, error) {
	if !env.AeadOn || len(env.Tag) == 0 {
		return frame, nil
	}
	if env.TagStart < 0 || env.TagStart > len(frame) {
		return nil, errors.New("invalid tag start")
	}
	return frame[:env.TagStart], nil
}
