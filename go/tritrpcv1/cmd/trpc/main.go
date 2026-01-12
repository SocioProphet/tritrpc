package main

import (
	"bufio"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	tr "github.com/example/tritrpcv1"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: trpc pack|verify ...")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "pack":
		fs := flag.NewFlagSet("pack", flag.ExitOnError)
		svc := fs.String("service", "", "service")
		method := fs.String("method", "", "method")
		jsonPath := fs.String("json", "", "json path (request/response)")
		nonceHex := fs.String("nonce", "", "24-byte nonce hex")
		keyHex := fs.String("key", "", "32-byte key hex")
		fs.Parse(os.Args[2:])
		if *svc == "" || *method == "" || *jsonPath == "" || *nonceHex == "" || *keyHex == "" {
			fs.Usage()
			os.Exit(1)
		}
		jb, err := os.ReadFile(*jsonPath)
		if err != nil {
			fmt.Println("read error:", err)
			os.Exit(1)
		}
		payload := buildFromJSON(*method, jb)
		key, _ := hex.DecodeString(*keyHex)
		nonce, _ := hex.DecodeString(*nonceHex)
		var k [32]byte
		copy(k[:], key[:32])
		var n [24]byte
		copy(n[:], nonce[:24])
		frame, _, _ := tr.EnvelopeWithTag(*svc, *method, payload, nil, k, n)
		fmt.Println(hex.EncodeToString(frame))
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		fixtures := fs.String("fixtures", "", "fixtures file")
		nonces := fs.String("nonces", "", "nonces file")
		fs.Parse(os.Args[2:])
		if *fixtures == "" || *nonces == "" {
			fs.Usage()
			os.Exit(1)
		}
		pairs := readPairs(*fixtures)
		nmap := readNonces(*nonces)
		key := [32]byte{}
		for _, p := range pairs {
			name := string(p[0])
			frame := p[1]
			env, err := tr.DecodeEnvelope(frame)
			if err != nil {
				fmt.Println("decode error for", name, ":", err)
				os.Exit(2)
			}
			if env.AeadOn {
				aad, err := tr.AADBeforeTag(frame, env)
				if err != nil {
					fmt.Println("aad error for", name, ":", err)
					os.Exit(2)
				}
				nonce := nmap[name]
				a, _ := chacha20poly1305.NewX(key[:])
				ct := a.Seal(nil, nonce, []byte{}, aad)
				computed := ct[len(ct)-16:]
				if subtle.ConstantTimeCompare(computed, env.Tag) != 1 {
					fmt.Println("tag mismatch for", name)
					os.Exit(2)
				}
			}
		}
		fmt.Println("OK:", *fixtures)
	default:
		fmt.Println("Usage: trpc pack|verify ...")
		os.Exit(1)
	}
}

func readPairs(path string) [][2][]byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	out := make([][2][]byte, 0)
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.SplitN(ln, " ", 2)
		name := []byte(parts[0])
		b, _ := hex.DecodeString(parts[1])
		out = append(out, [2][]byte{name, b})
	}
	return out
}

func readNonces(path string) map[string][]byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	out := map[string][]byte{}
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, " ", 2)
		key := parts[0]
		b, _ := hex.DecodeString(parts[1])
		out[key] = b
	}
	return out
}

/* JSON-driven payload builder (subset) */
func buildFromJSON(method string, jb []byte) []byte {
	type Vtx struct{ Vid, Label string }
	type Edge struct {
		Eid     string
		Members []string
		Weight  int64
	}
	type Req struct {
		Op     string
		Vertex *Vtx
		Edge   *Edge
		Vid    string
		Eid    string
		K      int32
	}
	var r Req
	if err := json.Unmarshal(jb, &r); err != nil {
		return tr.EncHGRequestAddVertex("a", strPtr("A"))
	}
	switch r.Op {
	case "AddVertex":
		if r.Vertex == nil {
			return tr.EncHGRequestAddVertex("a", strPtr("A"))
		}
		return tr.EncHGRequestAddVertex(r.Vertex.Vid, strPtr(r.Vertex.Label))
	case "AddHyperedge":
		if r.Edge == nil {
			return tr.EncHGRequestAddHyperedge("e1", []string{"a", "b"}, int64Ptr(1))
		}
		return tr.EncHGRequestAddHyperedge(r.Edge.Eid, r.Edge.Members, int64Ptr(r.Edge.Weight))
	case "QueryNeighbors":
		return tr.EncHGRequestQueryNeighbors(r.Vid, r.K)
	case "RemoveVertex":
		return tr.EncHGRequestRemoveVertex(r.Vid)
	case "RemoveHyperedge":
		return tr.EncHGRequestRemoveHyperedge(r.Eid)
	case "GetSubgraph":
		return tr.EncHGRequestGetSubgraph(r.Vid, r.K)
	default:
		return tr.EncHGRequestAddVertex("a", strPtr("A"))
	}
}

func strPtr(s string) *string { return &s }
func int64Ptr(v int64) *int64 { return &v }
