package tritrpcv1

func zigzag(n int64) uint64 {
	return uint64((n << 1) ^ (n >> 63))
}
func EncVarint(u uint64) []byte {
	out := []byte{}
	for (u & ^uint64(0x7F)) != 0 {
		out = append(out, byte(u&0x7F)|0x80)
		u >>= 7
	}
	out = append(out, byte(u))
	return out
}
func EncLong(n int64) []byte { return EncVarint(zigzag(n)) }
func EncInt(n int32) []byte  { return EncLong(int64(n)) }
func EncBool(v bool) []byte {
	if v {
		return []byte{1}
	}
	return []byte{0}
}
func EncString(s string) []byte {
	b := []byte(s)
	out := EncLong(int64(len(b)))
	out = append(out, b...)
	return out
}
func EncBytes(b []byte) []byte {
	out := EncLong(int64(len(b)))
	out = append(out, b...)
	return out
}
func EncArray(items [][]byte) []byte {
	if len(items) == 0 {
		return []byte{0}
	}
	out := EncLong(int64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	out = append(out, 0)
	return out
}
func EncMap(m map[string]string) []byte {
	if len(m) == 0 {
		return []byte{0}
	}
	out := EncLong(int64(len(m)))
	for k, v := range m {
		out = append(out, EncString(k)...)
		out = append(out, EncString(v)...)
	}
	out = append(out, 0)
	return out
}
func EncUnion(index int64, payload []byte) []byte {
	out := EncLong(index)
	out = append(out, payload...)
	return out
}
func EncEnum(index int32) []byte { return EncInt(index) }

// Control
func EncHello(modes, suites, comp []string, contextURI *string) []byte {
	arr := func(ss []string) []byte {
		chunks := make([][]byte, 0, len(ss))
		for _, s := range ss {
			chunks = append(chunks, EncString(s))
		}
		return EncArray(chunks)
	}
	out := []byte{}
	out = append(out, arr(modes)...)
	out = append(out, arr(suites)...)
	out = append(out, arr(comp)...)
	if contextURI == nil {
		out = append(out, EncUnion(0, []byte{})...)
	} else {
		out = append(out, EncUnion(1, EncString(*contextURI))...)
	}
	return out
}
func EncChoose(mode, suite, comp string) []byte {
	out := []byte{}
	out = append(out, EncString(mode)...)
	out = append(out, EncString(suite)...)
	out = append(out, EncString(comp)...)
	return out
}

// Hypergraph
func EncVertex(vid string, label *string, attr map[string]string) []byte {
	out := []byte{}
	out = append(out, EncString(vid)...)
	if label == nil {
		out = append(out, EncUnion(0, []byte{})...)
	} else {
		out = append(out, EncUnion(1, EncString(*label))...)
	}
	out = append(out, EncMap(attr)...)
	return out
}
func EncHyperedge(eid string, members []string, weight *int64, attr map[string]string) []byte {
	out := []byte{}
	out = append(out, EncString(eid)...)
	items := make([][]byte, 0, len(members))
	for _, m := range members {
		items = append(items, EncString(m))
	}
	out = append(out, EncArray(items)...)
	if weight == nil {
		out = append(out, EncUnion(0, []byte{})...)
	} else {
		out = append(out, EncUnion(1, EncLong(*weight))...)
	}
	out = append(out, EncMap(attr)...)
	return out
}
func EncHGRequestAddVertex(vid string, label *string) []byte {
	out := []byte{}
	out = append(out, EncEnum(0)...)
	out = append(out, EncUnion(1, EncVertex(vid, label, map[string]string{}))...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	return out
}
func EncHGRequestAddHyperedge(eid string, members []string, weight *int64) []byte {
	out := []byte{}
	out = append(out, EncEnum(1)...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncHyperedge(eid, members, weight, map[string]string{}))...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	return out
}
func EncHGRequestRemoveVertex(vid string) []byte {
	out := []byte{}
	out = append(out, EncEnum(2)...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncString(vid))...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	return out
}
func EncHGRequestRemoveHyperedge(eid string) []byte {
	out := []byte{}
	out = append(out, EncEnum(3)...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncString(eid))...)
	out = append(out, EncUnion(0, []byte{})...)
	return out
}
func EncHGRequestQueryNeighbors(vid string, k int32) []byte {
	out := []byte{}
	out = append(out, EncEnum(4)...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncString(vid))...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncInt(k))...)
	return out
}
func EncHGRequestGetSubgraph(vid string, k int32) []byte {
	out := []byte{}
	out = append(out, EncEnum(5)...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncString(vid))...)
	out = append(out, EncUnion(0, []byte{})...)
	out = append(out, EncUnion(1, EncInt(k))...)
	return out
}

func EncHGResponse(ok bool, err *string, vertices []Vertex, edges []Hyperedge) []byte {
	out := []byte{}
	out = append(out, EncBool(ok)...)
	if err == nil {
		out = append(out, EncUnion(0, []byte{})...)
	} else {
		out = append(out, EncUnion(1, EncString(*err))...)
	}
	vbytes := make([][]byte, 0, len(vertices))
	for _, v := range vertices {
		vbytes = append(vbytes, EncVertex(v.Vid, v.Label, v.Attr))
	}
	out = append(out, EncArray(vbytes)...)
	ebytes := make([][]byte, 0, len(edges))
	for _, e := range edges {
		ebytes = append(ebytes, EncHyperedge(e.Eid, e.Members, e.Weight, e.Attr))
	}
	out = append(out, EncArray(ebytes)...)
	return out
}
