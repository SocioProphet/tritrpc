package tritrpcv1

import "errors"

type Vertex struct {
	Vid   string
	Label *string
	Attr  map[string]string
}

type Hyperedge struct {
	Eid     string
	Members []string
	Weight  *int64
	Attr    map[string]string
}

type HGRequest struct {
	Op        int32
	Vertex    *Vertex
	Hyperedge *Hyperedge
	Vid       *string
	Eid       *string
	K         *int32
}

type HGResponse struct {
	Ok       bool
	Err      *string
	Vertices []Vertex
	Edges    []Hyperedge
}

func decVarint(buf []byte, off int) (uint64, int, error) {
	var out uint64
	var shift uint
	for {
		if off >= len(buf) {
			return 0, 0, errors.New("EOF in varint")
		}
		b := buf[off]
		off++
		out |= uint64(b&0x7F) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
		if shift > 63 {
			return 0, 0, errors.New("varint overflow")
		}
	}
	return out, off, nil
}

func decLong(buf []byte, off int) (int64, int, error) {
	u, no, err := decVarint(buf, off)
	if err != nil {
		return 0, 0, err
	}
	val := int64(u>>1) ^ -int64(u&1)
	return val, no, nil
}

func decInt(buf []byte, off int) (int32, int, error) {
	v, no, err := decLong(buf, off)
	return int32(v), no, err
}

func decBool(buf []byte, off int) (bool, int, error) {
	if off >= len(buf) {
		return false, 0, errors.New("EOF in bool")
	}
	return buf[off] != 0, off + 1, nil
}

func decString(buf []byte, off int) (string, int, error) {
	l, no, err := decLong(buf, off)
	if err != nil {
		return "", 0, err
	}
	if l < 0 {
		return "", 0, errors.New("negative string length")
	}
	end := no + int(l)
	if end > len(buf) {
		return "", 0, errors.New("string length exceeds buffer")
	}
	return string(buf[no:end]), end, nil
}

func decArrayStrings(buf []byte, off int) ([]string, int, error) {
	count, no, err := decLong(buf, off)
	if err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return []string{}, no, nil
	}
	if count < 0 {
		return nil, 0, errors.New("negative array block count")
	}
	out := make([]string, 0, count)
	for i := int64(0); i < count; i++ {
		s, n2, err := decString(buf, no)
		if err != nil {
			return nil, 0, err
		}
		no = n2
		out = append(out, s)
	}
	endCount, endOff, err := decLong(buf, no)
	if err != nil {
		return nil, 0, err
	}
	if endCount != 0 {
		return nil, 0, errors.New("non-zero array terminator")
	}
	return out, endOff, nil
}

func decMapStrings(buf []byte, off int) (map[string]string, int, error) {
	count, no, err := decLong(buf, off)
	if err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return map[string]string{}, no, nil
	}
	if count < 0 {
		return nil, 0, errors.New("negative map block count")
	}
	out := map[string]string{}
	for i := int64(0); i < count; i++ {
		k, n2, err := decString(buf, no)
		if err != nil {
			return nil, 0, err
		}
		v, n3, err := decString(buf, n2)
		if err != nil {
			return nil, 0, err
		}
		no = n3
		out[k] = v
	}
	endCount, endOff, err := decLong(buf, no)
	if err != nil {
		return nil, 0, err
	}
	if endCount != 0 {
		return nil, 0, errors.New("non-zero map terminator")
	}
	return out, endOff, nil
}

func decUnionIndex(buf []byte, off int) (int64, int, error) {
	return decLong(buf, off)
}

func decVertex(buf []byte, off int) (*Vertex, int, error) {
	vid, no, err := decString(buf, off)
	if err != nil {
		return nil, 0, err
	}
	idx, no, err := decUnionIndex(buf, no)
	if err != nil {
		return nil, 0, err
	}
	var label *string
	if idx == 1 {
		s, n2, err := decString(buf, no)
		if err != nil {
			return nil, 0, err
		}
		label = &s
		no = n2
	} else if idx != 0 {
		return nil, 0, errors.New("invalid union index for label")
	}
	attr, no, err := decMapStrings(buf, no)
	if err != nil {
		return nil, 0, err
	}
	return &Vertex{Vid: vid, Label: label, Attr: attr}, no, nil
}

func decHyperedge(buf []byte, off int) (*Hyperedge, int, error) {
	eid, no, err := decString(buf, off)
	if err != nil {
		return nil, 0, err
	}
	members, no, err := decArrayStrings(buf, no)
	if err != nil {
		return nil, 0, err
	}
	idx, no, err := decUnionIndex(buf, no)
	if err != nil {
		return nil, 0, err
	}
	var weight *int64
	if idx == 1 {
		w, n2, err := decLong(buf, no)
		if err != nil {
			return nil, 0, err
		}
		weight = &w
		no = n2
	} else if idx != 0 {
		return nil, 0, errors.New("invalid union index for weight")
	}
	attr, no, err := decMapStrings(buf, no)
	if err != nil {
		return nil, 0, err
	}
	return &Hyperedge{Eid: eid, Members: members, Weight: weight, Attr: attr}, no, nil
}

func DecodeHGRequest(buf []byte) (HGRequest, error) {
	op, off, err := decInt(buf, 0)
	if err != nil {
		return HGRequest{}, err
	}
	idxV, off, err := decUnionIndex(buf, off)
	if err != nil {
		return HGRequest{}, err
	}
	var vtx *Vertex
	if idxV == 1 {
		vtx, off, err = decVertex(buf, off)
		if err != nil {
			return HGRequest{}, err
		}
	} else if idxV != 0 {
		return HGRequest{}, errors.New("invalid union index for vertex")
	}
	idxE, off, err := decUnionIndex(buf, off)
	if err != nil {
		return HGRequest{}, err
	}
	var edge *Hyperedge
	if idxE == 1 {
		edge, off, err = decHyperedge(buf, off)
		if err != nil {
			return HGRequest{}, err
		}
	} else if idxE != 0 {
		return HGRequest{}, errors.New("invalid union index for hyperedge")
	}
	idxVid, off, err := decUnionIndex(buf, off)
	if err != nil {
		return HGRequest{}, err
	}
	var vid *string
	if idxVid == 1 {
		s, n2, err := decString(buf, off)
		if err != nil {
			return HGRequest{}, err
		}
		vid = &s
		off = n2
	} else if idxVid != 0 {
		return HGRequest{}, errors.New("invalid union index for vid")
	}
	idxEid, off, err := decUnionIndex(buf, off)
	if err != nil {
		return HGRequest{}, err
	}
	var eid *string
	if idxEid == 1 {
		s, n2, err := decString(buf, off)
		if err != nil {
			return HGRequest{}, err
		}
		eid = &s
		off = n2
	} else if idxEid != 0 {
		return HGRequest{}, errors.New("invalid union index for eid")
	}
	idxK, off, err := decUnionIndex(buf, off)
	if err != nil {
		return HGRequest{}, err
	}
	var k *int32
	if idxK == 1 {
		kv, n2, err := decInt(buf, off)
		if err != nil {
			return HGRequest{}, err
		}
		k = &kv
		off = n2
	} else if idxK != 0 {
		return HGRequest{}, errors.New("invalid union index for k")
	}
	if off != len(buf) {
		return HGRequest{}, errors.New("extra bytes after HGRequest")
	}
	return HGRequest{Op: op, Vertex: vtx, Hyperedge: edge, Vid: vid, Eid: eid, K: k}, nil
}

func EncodeHGRequest(req HGRequest) ([]byte, error) {
	switch req.Op {
	case 0:
		if req.Vertex == nil {
			return nil, errors.New("missing vertex")
		}
		if len(req.Vertex.Attr) != 0 {
			return nil, errors.New("vertex attr not supported in request encoder")
		}
		return EncHGRequestAddVertex(req.Vertex.Vid, req.Vertex.Label), nil
	case 1:
		if req.Hyperedge == nil {
			return nil, errors.New("missing hyperedge")
		}
		if len(req.Hyperedge.Attr) != 0 {
			return nil, errors.New("hyperedge attr not supported in request encoder")
		}
		return EncHGRequestAddHyperedge(req.Hyperedge.Eid, req.Hyperedge.Members, req.Hyperedge.Weight), nil
	case 2:
		if req.Vid == nil {
			return nil, errors.New("missing vid")
		}
		return EncHGRequestRemoveVertex(*req.Vid), nil
	case 3:
		if req.Eid == nil {
			return nil, errors.New("missing eid")
		}
		return EncHGRequestRemoveHyperedge(*req.Eid), nil
	case 4:
		if req.Vid == nil {
			return nil, errors.New("missing vid")
		}
		k := int32(1)
		if req.K != nil {
			k = *req.K
		}
		return EncHGRequestQueryNeighbors(*req.Vid, k), nil
	case 5:
		if req.Vid == nil {
			return nil, errors.New("missing vid")
		}
		k := int32(1)
		if req.K != nil {
			k = *req.K
		}
		return EncHGRequestGetSubgraph(*req.Vid, k), nil
	default:
		return nil, errors.New("unsupported op")
	}
}

func DecodeHGResponse(buf []byte) (HGResponse, error) {
	ok, off, err := decBool(buf, 0)
	if err != nil {
		return HGResponse{}, err
	}
	idxErr, off, err := decUnionIndex(buf, off)
	if err != nil {
		return HGResponse{}, err
	}
	var errStr *string
	if idxErr == 1 {
		s, n2, err := decString(buf, off)
		if err != nil {
			return HGResponse{}, err
		}
		errStr = &s
		off = n2
	} else if idxErr != 0 {
		return HGResponse{}, errors.New("invalid union index for err")
	}
	vcount, off, err := decLong(buf, off)
	if err != nil {
		return HGResponse{}, err
	}
	vertices := []Vertex{}
	if vcount < 0 {
		return HGResponse{}, errors.New("negative vertices block")
	}
	if vcount > 0 {
		for i := int64(0); i < vcount; i++ {
			v, n2, err := decVertex(buf, off)
			if err != nil {
				return HGResponse{}, err
			}
			if len(v.Attr) != 0 {
				return HGResponse{}, errors.New("vertex attr not supported in response fixtures")
			}
			vertices = append(vertices, *v)
			off = n2
		}
		endCount, endOff, err := decLong(buf, off)
		if err != nil {
			return HGResponse{}, err
		}
		if endCount != 0 {
			return HGResponse{}, errors.New("non-zero vertices terminator")
		}
		off = endOff
	}
	ecount, off, err := decLong(buf, off)
	if err != nil {
		return HGResponse{}, err
	}
	edges := []Hyperedge{}
	if ecount < 0 {
		return HGResponse{}, errors.New("negative edges block")
	}
	if ecount > 0 {
		for i := int64(0); i < ecount; i++ {
			e, n2, err := decHyperedge(buf, off)
			if err != nil {
				return HGResponse{}, err
			}
			if len(e.Attr) != 0 {
				return HGResponse{}, errors.New("edge attr not supported in response fixtures")
			}
			edges = append(edges, *e)
			off = n2
		}
		endCount, endOff, err := decLong(buf, off)
		if err != nil {
			return HGResponse{}, err
		}
		if endCount != 0 {
			return HGResponse{}, errors.New("non-zero edges terminator")
		}
		off = endOff
	}
	if off != len(buf) {
		return HGResponse{}, errors.New("extra bytes after HGResponse")
	}
	return HGResponse{Ok: ok, Err: errStr, Vertices: vertices, Edges: edges}, nil
}

func EncodeHGResponse(resp HGResponse) ([]byte, error) {
	return EncHGResponse(resp.Ok, resp.Err, resp.Vertices, resp.Edges), nil
}
