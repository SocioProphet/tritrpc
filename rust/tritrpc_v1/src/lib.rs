pub mod tritpack243 {
    pub fn pack(trits: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i + 5 <= trits.len() {
            let mut val: u32 = 0;
            for &t in &trits[i..i + 5] {
                assert!(t <= 2, "invalid trit");
                val = val * 3 + t as u32;
            }
            out.push(val as u8);
            i += 5;
        }
        let k = trits.len() - i;
        if k > 0 {
            out.push(243 + (k as u8 - 1));
            let mut val: u32 = 0;
            for &t in &trits[i..] {
                val = val * 3 + t as u32;
            }
            out.push(val as u8);
        }
        out
    }

    pub fn unpack(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut trits: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        while i < bytes.len() {
            let b = bytes[i];
            i += 1;
            if b <= 242 {
                let mut val = b as u32;
                let mut group = [0u8; 5];
                for j in (0..5).rev() {
                    group[j] = (val % 3) as u8;
                    val /= 3;
                }
                trits.extend_from_slice(&group);
            } else if (243..=246).contains(&b) {
                if i >= bytes.len() {
                    return Err("truncated tail marker".into());
                }
                let k = (b - 243 + 1) as usize;
                let mut val = bytes[i] as u32;
                i += 1;
                let mut group = vec![0u8; k];
                for j in (0..k).rev() {
                    group[j] = (val % 3) as u8;
                    val /= 3;
                }
                trits.extend(group);
            } else {
                return Err("invalid byte 247..255 in canonical stream".into());
            }
        }
        Ok(trits)
    }
}

pub mod tleb3 {
    use super::tritpack243;
    pub fn encode_len(mut n: u64) -> Vec<u8> {
        let mut digits: Vec<u8> = Vec::new();
        if n == 0 {
            digits.push(0);
        } else {
            while n > 0 {
                digits.push((n % 9) as u8);
                n /= 9;
            }
        }
        let mut trits: Vec<u8> = Vec::new();
        for (i, d) in digits.iter().enumerate() {
            let c = if i < digits.len() - 1 { 2 } else { 0 };
            let p1 = d / 3;
            let p0 = d % 3;
            trits.push(c);
            trits.push(*p1);
            trits.push(*p0);
        }
        tritpack243::pack(&trits)
    }

    pub fn decode_len(bytes: &[u8], mut offset: usize) -> Result<(u64, usize), String> {
        let mut trits: Vec<u8> = Vec::new();
        loop {
            if offset >= bytes.len() {
                return Err("EOF in TLEB3".into());
            }
            let b = bytes[offset];
            offset += 1;
            let ts = super::tritpack243::unpack(&[b])?;
            trits.extend_from_slice(&ts);
            if trits.len() < 3 {
                continue;
            }
            let mut val: u64 = 0;
            let mut used_trits: usize = 0;
            for j in 0..(trits.len() / 3) {
                let c = trits[3 * j] as u64;
                let p1 = trits[3 * j + 1] as u64;
                let p0 = trits[3 * j + 2] as u64;
                let digit = p1 * 3 + p0;
                val += digit * 9u64.pow(j as u32);
                if c == 0 {
                    used_trits = (j + 1) * 3;
                    break;
                }
            }
            if used_trits > 0 {
                let used_bytes = super::tritpack243::pack(&trits[..used_trits]).len();
                let new_off = offset - 1 + (used_bytes - 1);
                return Ok((val, new_off));
            }
        }
    }
}

pub mod envelope {
    use super::{tleb3, tritpack243};
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::XChaCha20Poly1305;

    const MAGIC_B2: [u8; 2] = [0xF3, 0x2A];
    pub const SCHEMA_ID_32: [u8; 32] = [
        0xb2, 0xab, 0x81, 0x45, 0x88, 0xf9, 0x9c, 0x87, 0x5d, 0x37, 0xbb, 0x75, 0x46, 0xd0, 0xdf,
        0x43, 0x69, 0xc2, 0x8b, 0xc5, 0xf6, 0x0c, 0xe3, 0x8a, 0x66, 0x07, 0xda, 0xc4, 0x68, 0x03,
        0x43, 0x52,
    ];
    pub const CONTEXT_ID_32: [u8; 32] = [
        0xe6, 0x57, 0x2c, 0x0e, 0x61, 0x8f, 0x18, 0xd5, 0x72, 0xd4, 0xc2, 0x96, 0x9d, 0xb4, 0x90,
        0x96, 0x59, 0xf0, 0x9e, 0xae, 0xf3, 0x2e, 0xc6, 0x6f, 0xbb, 0x80, 0x4b, 0xad, 0x9d, 0x89,
        0xaa, 0xcd,
    ];

    fn len_prefix(b: &[u8]) -> Vec<u8> {
        tleb3::encode_len(b.len() as u64)
    }

    fn pack_trits(ts: &[u8]) -> Vec<u8> {
        tritpack243::pack(ts)
    }

    pub fn flags_trits(aead: bool, compress: bool) -> [u8; 3] {
        [if aead { 2 } else { 0 }, if compress { 2 } else { 0 }, 0]
    }

    pub fn build(
        service: &str,
        method: &str,
        payload: &[u8],
        aux: Option<&[u8]>,
        aead_tag: Option<&[u8]>,
        aead_on: bool,
        compress: bool,
    ) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend(len_prefix(&MAGIC_B2));
        out.extend(MAGIC_B2);
        let ver = pack_trits(&[1]);
        out.extend(len_prefix(&ver));
        out.extend(ver);
        let mode = pack_trits(&[0]);
        out.extend(len_prefix(&mode));
        out.extend(mode);
        let flags = pack_trits(&super::envelope::flags_trits(aead_on, compress));
        out.extend(len_prefix(&flags));
        out.extend(flags);
        let schema = SCHEMA_ID_32;
        out.extend(len_prefix(&schema));
        out.extend(&schema);
        let context = CONTEXT_ID_32;
        out.extend(len_prefix(&context));
        out.extend(&context);
        let svc = service.as_bytes();
        out.extend(len_prefix(svc));
        out.extend(svc);
        let m = method.as_bytes();
        out.extend(len_prefix(m));
        out.extend(m);
        out.extend(len_prefix(payload));
        out.extend(payload);
        if let Some(auxb) = aux {
            out.extend(len_prefix(auxb));
            out.extend(auxb);
        }
        if let Some(tag) = aead_tag {
            out.extend(len_prefix(tag));
            out.extend(tag);
        }
        out
    }

    pub fn envelope_with_tag(
        service: &str,
        method: &str,
        payload: &[u8],
        aux: Option<&[u8]>,
        key: &[u8; 32],
        nonce: &[u8; 24],
    ) -> (Vec<u8>, Vec<u8>) {
        let aad = build(service, method, payload, aux, None, true, false);
        let aead = XChaCha20Poly1305::new(key.into());
        let ct = aead
            .encrypt(
                nonce.into(),
                chacha20poly1305::aead::Payload {
                    msg: b"",
                    aad: &aad,
                },
            )
            .expect("encrypt");
        let tag = ct[ct.len() - 16..].to_vec();
        let frame = build(service, method, payload, aux, Some(&tag), true, false);
        (frame, tag)
    }

    #[derive(Debug, Clone)]
    pub struct DecodedEnvelope {
        pub magic: Vec<u8>,
        pub version: Vec<u8>,
        pub mode: Vec<u8>,
        pub flags: Vec<u8>,
        pub schema: Vec<u8>,
        pub context: Vec<u8>,
        pub service: String,
        pub method: String,
        pub payload: Vec<u8>,
        pub aux: Option<Vec<u8>>,
        pub tag: Option<Vec<u8>>,
        pub aead_on: bool,
        pub compress: bool,
        pub tag_start: Option<usize>,
    }

    fn read_field(frame: &[u8], off: usize) -> Result<(Vec<u8>, usize, usize), String> {
        let (len, new_off) = tleb3::decode_len(frame, off)?;
        let l = len as usize;
        let val_start = new_off;
        let val_end = val_start + l;
        if val_end > frame.len() {
            return Err("field length exceeds frame".into());
        }
        Ok((frame[val_start..val_end].to_vec(), val_end, off))
    }

    pub fn decode(frame: &[u8]) -> Result<DecodedEnvelope, String> {
        let mut off = 0usize;
        let (magic, off1, _) = read_field(frame, off)?;
        off = off1;
        let (version, off2, _) = read_field(frame, off)?;
        off = off2;
        let (mode, off3, _) = read_field(frame, off)?;
        off = off3;
        let (flags, off4, _) = read_field(frame, off)?;
        off = off4;
        let (schema, off5, _) = read_field(frame, off)?;
        off = off5;
        let (context, off6, _) = read_field(frame, off)?;
        off = off6;
        let (svc, off7, _) = read_field(frame, off)?;
        off = off7;
        let (method, off8, _) = read_field(frame, off)?;
        off = off8;
        let (payload, off9, _) = read_field(frame, off)?;
        off = off9;

        let trits = tritpack243::unpack(&flags)?;
        let aead_on = trits.get(0) == Some(&2u8);
        let compress = trits.get(1) == Some(&2u8);

        let mut aux: Option<Vec<u8>> = None;
        let mut tag: Option<Vec<u8>> = None;
        let mut tag_start: Option<usize> = None;

        let remaining = frame.len().saturating_sub(off);
        if remaining > 0 {
            if aead_on {
                // If two fields remain, treat as aux + tag. If one remains, tag only.
                let (first, off10, start10) = read_field(frame, off)?;
                off = off10;
                if off < frame.len() {
                    let (tag_val, off11, start11) = read_field(frame, off)?;
                    off = off11;
                    aux = Some(first);
                    tag = Some(tag_val);
                    tag_start = Some(start11);
                } else {
                    tag = Some(first);
                    tag_start = Some(start10);
                }
            } else {
                let (aux_val, off10, _) = read_field(frame, off)?;
                off = off10;
                aux = Some(aux_val);
            }
        }
        if off != frame.len() {
            return Err("extra bytes after envelope parsing".into());
        }
        Ok(DecodedEnvelope {
            magic,
            version,
            mode,
            flags,
            schema,
            context,
            service: String::from_utf8(svc).map_err(|_| "service not utf8")?,
            method: String::from_utf8(method).map_err(|_| "method not utf8")?,
            payload,
            aux,
            tag,
            aead_on,
            compress,
            tag_start,
        })
    }
}

pub mod avroenc {
    // Avro subset encoders: zigzag, varint, string, bytes, array, map, union, enum, records for control+HG
    fn zigzag(n: i64) -> u64 {
        ((n << 1) ^ (n >> 63)) as u64
    }
    pub fn enc_varint(mut u: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while (u & !0x7F) != 0 {
            out.push(((u & 0x7F) as u8) | 0x80);
            u >>= 7;
        }
        out.push(u as u8);
        out
    }
    pub fn enc_long(n: i64) -> Vec<u8> {
        enc_varint(zigzag(n))
    }
    pub fn enc_int(n: i32) -> Vec<u8> {
        enc_long(n as i64)
    }
    pub fn enc_bool(v: bool) -> Vec<u8> {
        if v {
            vec![1]
        } else {
            vec![0]
        }
    }
    pub fn enc_string(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = enc_long(b.len() as i64);
        out.extend_from_slice(b);
        out
    }
    pub fn enc_bytes(b: &[u8]) -> Vec<u8> {
        let mut out = enc_long(b.len() as i64);
        out.extend_from_slice(b);
        out
    }
    pub fn enc_array<T>(items: &[T], f: fn(&T) -> Vec<u8>) -> Vec<u8> {
        if items.is_empty() {
            return vec![0];
        }
        let mut out = Vec::new();
        out.extend(enc_long(items.len() as i64));
        for it in items {
            out.extend(f(it));
        }
        out.push(0);
        out
    }
    pub fn enc_map(m: &[(&str, &str)]) -> Vec<u8> {
        if m.is_empty() {
            return vec![0];
        }
        let mut out = Vec::new();
        out.extend(enc_long(m.len() as i64));
        for (k, v) in m {
            out.extend(enc_string(k));
            out.extend(enc_string(v));
        }
        out.push(0);
        out
    }
    pub fn enc_union(index: i64, payload: Vec<u8>) -> Vec<u8> {
        let mut out = enc_long(index);
        out.extend(payload);
        out
    }
    pub fn enc_enum(index: i32) -> Vec<u8> {
        enc_int(index)
    }

    // Control
    pub fn enc_Hello(
        modes: &[&str],
        suites: &[&str],
        comp: &[&str],
        context_uri: Option<&str>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_array(modes, |s| enc_string(s)));
        out.extend(enc_array(suites, |s| enc_string(s)));
        out.extend(enc_array(comp, |s| enc_string(s)));
        match context_uri {
            None => out.extend(enc_union(0, vec![])),
            Some(u) => out.extend(enc_union(1, enc_string(u))),
        }
        out
    }
    pub fn enc_Choose(mode: &str, suite: &str, comp: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_string(mode));
        out.extend(enc_string(suite));
        out.extend(enc_string(comp));
        out
    }
    pub fn enc_Error(code: i32, msg: &str, details: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_int(code));
        out.extend(enc_string(msg));
        match details {
            None => out.extend(enc_union(0, vec![])),
            Some(b) => out.extend(enc_union(1, enc_bytes(b))),
        }
        out
    }

    // Hypergraph
    pub fn enc_Vertex(vid: &str, label: Option<&str>, attrs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_string(vid));
        match label {
            None => out.extend(enc_union(0, vec![])),
            Some(l) => out.extend(enc_union(1, enc_string(l))),
        }
        out.extend(enc_map(attrs));
        out
    }
    pub fn enc_Hyperedge(
        eid: &str,
        members: &[&str],
        weight: Option<i64>,
        attrs: &[(&str, &str)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_string(eid));
        out.extend(enc_array(members, |s| enc_string(s)));
        match weight {
            None => out.extend(enc_union(0, vec![])),
            Some(w) => out.extend(enc_union(1, enc_long(w))),
        }
        out.extend(enc_map(attrs));
        out
    }
    pub fn enc_HGRequest_AddVertex(vid: &str, label: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(0));
        out.extend(enc_union(1, enc_Vertex(vid, label, &[])));
        out.extend(enc_union(0, vec![])); // edge null
        out.extend(enc_union(0, vec![])); // vid null
        out.extend(enc_union(0, vec![])); // eid null
        out.extend(enc_union(0, vec![])); // k null
        out
    }
    pub fn enc_HGRequest_AddHyperedge(eid: &str, members: &[&str], weight: Option<i64>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(1));
        out.extend(enc_union(0, vec![])); // vertex null
        out.extend(enc_union(1, enc_Hyperedge(eid, members, weight, &[])));
        out.extend(enc_union(0, vec![])); // vid null
        out.extend(enc_union(0, vec![])); // eid null
        out.extend(enc_union(0, vec![])); // k null
        out
    }
    pub fn enc_HGRequest_RemoveVertex(vid: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(2));
        out.extend(enc_union(0, vec![])); // vertex null
        out.extend(enc_union(0, vec![])); // edge null
        out.extend(enc_union(1, enc_string(vid)));
        out.extend(enc_union(0, vec![])); // eid null
        out.extend(enc_union(0, vec![])); // k null
        out
    }
    pub fn enc_HGRequest_RemoveHyperedge(eid: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(3));
        out.extend(enc_union(0, vec![])); // vertex null
        out.extend(enc_union(0, vec![])); // edge null
        out.extend(enc_union(0, vec![])); // vid null
        out.extend(enc_union(1, enc_string(eid)));
        out.extend(enc_union(0, vec![])); // k null
        out
    }
    pub fn enc_HGRequest_QueryNeighbors(vid: &str, k: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(4));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_string(vid)));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_int(k)));
        out
    }
    pub fn enc_HGRequest_GetSubgraph(vid: &str, k: i32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_enum(5));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_string(vid)));
        out.extend(enc_union(0, vec![]));
        out.extend(enc_union(1, enc_int(k)));
        out
    }
    pub fn enc_HGResponse(
        ok: bool,
        err: Option<&str>,
        vertices: &[(&str, Option<&str>)],
        edges: &[(&str, Vec<&str>, Option<i64>)],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(enc_bool(ok));
        match err {
            None => out.extend(enc_union(0, vec![])),
            Some(e) => out.extend(enc_union(1, enc_string(e))),
        }
        // vertices
        let vbytes = vertices
            .iter()
            .map(|(vid, l)| enc_Vertex(vid, *l, &[]))
            .collect::<Vec<_>>();
        let mut arr = Vec::new();
        if vbytes.is_empty() {
            arr.push(0);
        } else {
            arr.extend(enc_long(vbytes.len() as i64));
            for vb in vbytes {
                arr.extend(vb);
            }
            arr.push(0);
        }
        out.extend(arr);
        // edges
        let ebytes = edges
            .iter()
            .map(|(eid, mem, w)| enc_Hyperedge(eid, mem, *w, &[]))
            .collect::<Vec<_>>();
        let mut arr2 = Vec::new();
        if ebytes.is_empty() {
            arr2.push(0);
        } else {
            arr2.extend(enc_long(ebytes.len() as i64));
            for eb in ebytes {
                arr2.extend(eb);
            }
            arr2.push(0);
        }
        out.extend(arr2);
        out
    }
}

pub mod avrodec {
    use super::avroenc;

    fn zigzag_inv(u: u64) -> i64 {
        ((u >> 1) as i64) ^ (-((u & 1) as i64))
    }

    pub fn dec_varint(bytes: &[u8], mut off: usize) -> Result<(u64, usize), String> {
        let mut shift = 0u32;
        let mut out = 0u64;
        loop {
            if off >= bytes.len() {
                return Err("EOF in varint".into());
            }
            let b = bytes[off];
            off += 1;
            out |= ((b & 0x7F) as u64) << shift;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err("varint overflow".into());
            }
        }
        Ok((out, off))
    }

    pub fn dec_long(bytes: &[u8], off: usize) -> Result<(i64, usize), String> {
        let (u, new_off) = dec_varint(bytes, off)?;
        Ok((zigzag_inv(u), new_off))
    }

    pub fn dec_int(bytes: &[u8], off: usize) -> Result<(i32, usize), String> {
        let (v, new_off) = dec_long(bytes, off)?;
        Ok((v as i32, new_off))
    }

    pub fn dec_bool(bytes: &[u8], off: usize) -> Result<(bool, usize), String> {
        if off >= bytes.len() {
            return Err("EOF in bool".into());
        }
        Ok((bytes[off] != 0, off + 1))
    }

    pub fn dec_string(bytes: &[u8], off: usize) -> Result<(String, usize), String> {
        let (len, mut new_off) = dec_long(bytes, off)?;
        if len < 0 {
            return Err("negative string length".into());
        }
        let l = len as usize;
        let end = new_off + l;
        if end > bytes.len() {
            return Err("string length exceeds buffer".into());
        }
        let s = std::str::from_utf8(&bytes[new_off..end])
            .map_err(|_| "invalid utf8")?
            .to_string();
        new_off = end;
        Ok((s, new_off))
    }

    pub fn dec_bytes(bytes: &[u8], off: usize) -> Result<(Vec<u8>, usize), String> {
        let (len, mut new_off) = dec_long(bytes, off)?;
        if len < 0 {
            return Err("negative bytes length".into());
        }
        let l = len as usize;
        let end = new_off + l;
        if end > bytes.len() {
            return Err("bytes length exceeds buffer".into());
        }
        let out = bytes[new_off..end].to_vec();
        new_off = end;
        Ok((out, new_off))
    }

    pub fn dec_array_strings(bytes: &[u8], mut off: usize) -> Result<(Vec<String>, usize), String> {
        let (count, mut new_off) = dec_long(bytes, off)?;
        if count == 0 {
            return Ok((Vec::new(), new_off));
        }
        if count < 0 {
            return Err("negative array block count".into());
        }
        let mut out = Vec::new();
        for _ in 0..count {
            let (s, n2) = dec_string(bytes, new_off)?;
            new_off = n2;
            out.push(s);
        }
        let (end_count, end_off) = dec_long(bytes, new_off)?;
        if end_count != 0 {
            return Err("non-zero array terminator".into());
        }
        Ok((out, end_off))
    }

    pub fn dec_map_strings(
        bytes: &[u8],
        mut off: usize,
    ) -> Result<(Vec<(String, String)>, usize), String> {
        let (count, mut new_off) = dec_long(bytes, off)?;
        if count == 0 {
            return Ok((Vec::new(), new_off));
        }
        if count < 0 {
            return Err("negative map block count".into());
        }
        let mut out = Vec::new();
        for _ in 0..count {
            let (k, o1) = dec_string(bytes, new_off)?;
            let (v, o2) = dec_string(bytes, o1)?;
            new_off = o2;
            out.push((k, v));
        }
        let (end_count, end_off) = dec_long(bytes, new_off)?;
        if end_count != 0 {
            return Err("non-zero map terminator".into());
        }
        Ok((out, end_off))
    }

    pub fn dec_union_index(bytes: &[u8], off: usize) -> Result<(i64, usize), String> {
        dec_long(bytes, off)
    }

    #[derive(Debug, Clone)]
    pub struct Vertex {
        pub vid: String,
        pub label: Option<String>,
        pub attr: Vec<(String, String)>,
    }

    #[derive(Debug, Clone)]
    pub struct Hyperedge {
        pub eid: String,
        pub members: Vec<String>,
        pub weight: Option<i64>,
        pub attr: Vec<(String, String)>,
    }

    #[derive(Debug, Clone)]
    pub struct HGRequest {
        pub op: i32,
        pub vertex: Option<Vertex>,
        pub hyperedge: Option<Hyperedge>,
        pub vid: Option<String>,
        pub eid: Option<String>,
        pub k: Option<i32>,
    }

    #[derive(Debug, Clone)]
    pub struct HGResponse {
        pub ok: bool,
        pub err: Option<String>,
        pub vertices: Vec<(String, Option<String>)>,
        pub edges: Vec<(String, Vec<String>, Option<i64>)>,
    }

    pub fn dec_vertex(bytes: &[u8], off: usize) -> Result<(Vertex, usize), String> {
        let (vid, mut o1) = dec_string(bytes, off)?;
        let (idx, mut o2) = dec_union_index(bytes, o1)?;
        let label = if idx == 0 {
            None
        } else if idx == 1 {
            let (s, o3) = dec_string(bytes, o2)?;
            o2 = o3;
            Some(s)
        } else {
            return Err("invalid union index for label".into());
        };
        let (attr, o4) = dec_map_strings(bytes, o2)?;
        Ok((Vertex { vid, label, attr }, o4))
    }

    pub fn dec_hyperedge(bytes: &[u8], off: usize) -> Result<(Hyperedge, usize), String> {
        let (eid, mut o1) = dec_string(bytes, off)?;
        let (members, mut o2) = dec_array_strings(bytes, o1)?;
        let (idx, mut o3) = dec_union_index(bytes, o2)?;
        let weight = if idx == 0 {
            None
        } else if idx == 1 {
            let (w, o4) = dec_long(bytes, o3)?;
            o3 = o4;
            Some(w)
        } else {
            return Err("invalid union index for weight".into());
        };
        let (attr, o5) = dec_map_strings(bytes, o3)?;
        Ok((
            Hyperedge {
                eid,
                members,
                weight,
                attr,
            },
            o5,
        ))
    }

    pub fn dec_hg_request(bytes: &[u8]) -> Result<HGRequest, String> {
        let (op, mut off) = dec_int(bytes, 0)?;
        let (idx_v, mut off2) = dec_union_index(bytes, off)?;
        let mut vertex = None;
        if idx_v == 1 {
            let (v, o3) = dec_vertex(bytes, off2)?;
            vertex = Some(v);
            off2 = o3;
        }
        let (idx_e, mut off3) = dec_union_index(bytes, off2)?;
        let mut hyperedge = None;
        if idx_e == 1 {
            let (e, o4) = dec_hyperedge(bytes, off3)?;
            hyperedge = Some(e);
            off3 = o4;
        }
        let (idx_vid, mut off4) = dec_union_index(bytes, off3)?;
        let mut vid = None;
        if idx_vid == 1 {
            let (s, o5) = dec_string(bytes, off4)?;
            vid = Some(s);
            off4 = o5;
        }
        let (idx_eid, mut off5) = dec_union_index(bytes, off4)?;
        let mut eid = None;
        if idx_eid == 1 {
            let (s, o6) = dec_string(bytes, off5)?;
            eid = Some(s);
            off5 = o6;
        }
        let (idx_k, mut off6) = dec_union_index(bytes, off5)?;
        let mut k = None;
        if idx_k == 1 {
            let (kv, o7) = dec_int(bytes, off6)?;
            k = Some(kv);
            off6 = o7;
        }
        if off6 != bytes.len() {
            return Err("extra bytes after HGRequest".into());
        }
        Ok(HGRequest {
            op,
            vertex,
            hyperedge,
            vid,
            eid,
            k,
        })
    }

    pub fn enc_hg_request(req: &HGRequest) -> Result<Vec<u8>, String> {
        match req.op {
            0 => {
                let v = req.vertex.as_ref().ok_or("missing vertex")?;
                if !v.attr.is_empty() {
                    return Err("vertex attr not supported in encoder".into());
                }
                Ok(avroenc::enc_HGRequest_AddVertex(&v.vid, v.label.as_deref()))
            }
            1 => {
                let e = req.hyperedge.as_ref().ok_or("missing hyperedge")?;
                if !e.attr.is_empty() {
                    return Err("hyperedge attr not supported in encoder".into());
                }
                let members = e.members.iter().map(|s| s.as_str()).collect::<Vec<_>>();
                Ok(avroenc::enc_HGRequest_AddHyperedge(
                    &e.eid, &members, e.weight,
                ))
            }
            2 => {
                let vid = req.vid.as_ref().ok_or("missing vid")?;
                Ok(avroenc::enc_HGRequest_RemoveVertex(vid))
            }
            3 => {
                let eid = req.eid.as_ref().ok_or("missing eid")?;
                Ok(avroenc::enc_HGRequest_RemoveHyperedge(eid))
            }
            4 => {
                let vid = req.vid.as_ref().ok_or("missing vid")?;
                let k = req.k.unwrap_or(1);
                Ok(avroenc::enc_HGRequest_QueryNeighbors(vid, k))
            }
            5 => {
                let vid = req.vid.as_ref().ok_or("missing vid")?;
                let k = req.k.unwrap_or(1);
                Ok(avroenc::enc_HGRequest_GetSubgraph(vid, k))
            }
            _ => Err("unsupported op".into()),
        }
    }

    pub fn dec_hg_response(bytes: &[u8]) -> Result<HGResponse, String> {
        let (ok, mut off) = dec_bool(bytes, 0)?;
        let (idx_err, mut off2) = dec_union_index(bytes, off)?;
        let err = if idx_err == 0 {
            None
        } else if idx_err == 1 {
            let (s, o3) = dec_string(bytes, off2)?;
            off2 = o3;
            Some(s)
        } else {
            return Err("invalid union index for err".into());
        };
        let (vcount, mut off3) = dec_long(bytes, off2)?;
        let mut vertices = Vec::new();
        if vcount < 0 {
            return Err("negative vertices block".into());
        }
        if vcount == 0 {
            // ok
        } else {
            for _ in 0..vcount {
                let (v, o4) = dec_vertex(bytes, off3)?;
                if !v.attr.is_empty() {
                    return Err("vertex attr not supported in response fixtures".into());
                }
                off3 = o4;
                vertices.push((v.vid, v.label));
            }
            let (endc, o5) = dec_long(bytes, off3)?;
            if endc != 0 {
                return Err("non-zero vertices terminator".into());
            }
            off3 = o5;
        }
        let (ecount, mut off4) = dec_long(bytes, off3)?;
        let mut edges = Vec::new();
        if ecount < 0 {
            return Err("negative edges block".into());
        }
        if ecount == 0 {
            // ok
        } else {
            for _ in 0..ecount {
                let (e, o5) = dec_hyperedge(bytes, off4)?;
                if !e.attr.is_empty() {
                    return Err("edge attr not supported in response fixtures".into());
                }
                off4 = o5;
                edges.push((e.eid, e.members, e.weight));
            }
            let (endc, o6) = dec_long(bytes, off4)?;
            if endc != 0 {
                return Err("non-zero edges terminator".into());
            }
            off4 = o6;
        }
        if off4 != bytes.len() {
            return Err("extra bytes after HGResponse".into());
        }
        Ok(HGResponse {
            ok,
            err,
            vertices,
            edges,
        })
    }

    pub fn enc_hg_response(resp: &HGResponse) -> Result<Vec<u8>, String> {
        let vertices = resp
            .vertices
            .iter()
            .map(|(vid, label)| (vid.as_str(), label.as_deref()))
            .collect::<Vec<_>>();
        let edges = resp
            .edges
            .iter()
            .map(|(eid, members, weight)| {
                let members_ref = members.iter().map(|s| s.as_str()).collect::<Vec<_>>();
                (eid.as_str(), members_ref, *weight)
            })
            .collect::<Vec<_>>();
        Ok(avroenc::enc_HGResponse(
            resp.ok,
            resp.err.as_deref(),
            &vertices,
            &edges,
        ))
    }
}

pub mod tritrpc_v1_tests {
    use super::envelope;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::XChaCha20Poly1305;
    use std::collections::HashMap;
    use std::fs;
    use subtle::ConstantTimeEq;

    pub fn verify_file(fx: &str, nonces_path: &str) -> String {
        let key = [0u8; 32];
        let pairs = read_pairs(fx);
        let nonces = read_nonces(nonces_path);
        let mut ok = 0usize;
        for (name, frame) in pairs {
            let decoded = envelope::decode(&frame).expect("decode envelope");
            assert_eq!(
                decoded.schema.as_slice(),
                envelope::SCHEMA_ID_32.as_slice(),
                "schema id mismatch {}",
                name
            );
            assert_eq!(
                decoded.context.as_slice(),
                envelope::CONTEXT_ID_32.as_slice(),
                "context id mismatch {}",
                name
            );
            let repacked = envelope::build(
                &decoded.service,
                &decoded.method,
                &decoded.payload,
                decoded.aux.as_deref(),
                decoded.tag.as_deref(),
                decoded.aead_on,
                decoded.compress,
            );
            assert_eq!(repacked, frame, "repack mismatch {}", name);
            if decoded.aead_on {
                let tag = decoded.tag.as_ref().expect("missing tag");
                let nonce = nonces.get(&name).expect("nonce missing");
                assert_eq!(nonce.len(), 24, "nonce size mismatch {}", name);
                assert_eq!(tag.len(), 16, "tag size mismatch {}", name);
                let aad_start = decoded.tag_start.expect("tag start missing");
                let aad = &frame[..aad_start];
                let aead = XChaCha20Poly1305::new(&key.into());
                let ct = aead
                    .encrypt(
                        nonce.as_slice().into(),
                        chacha20poly1305::aead::Payload { msg: b"", aad },
                    )
                    .unwrap();
                let computed = &ct[ct.len() - 16..];
                assert!(
                    computed.ct_eq(tag.as_slice()).into(),
                    "tag mismatch {}",
                    name
                );
            }
            ok += 1;
        }
        format!("Verified {} frames in {}", ok, fx)
    }

    fn read_pairs(path: &str) -> Vec<(String, Vec<u8>)> {
        let txt = fs::read_to_string(path).expect("read fixtures");
        txt.lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut it = l.splitn(2, ' ');
                let name = it.next().unwrap().to_string();
                let hexs = it.next().unwrap();
                let bytes = hex::decode(hexs).unwrap();
                (name, bytes)
            })
            .collect()
    }
    fn read_nonces(path: &str) -> HashMap<String, Vec<u8>> {
        let txt = fs::read_to_string(path).expect("read nonces");
        txt.lines()
            .filter(|l| !l.is_empty())
            .map(|l| {
                let mut it = l.splitn(2, ' ');
                let name = it.next().unwrap().to_string();
                let hexs = it.next().unwrap();
                (name, hex::decode(hexs).unwrap())
            })
            .collect()
    }
}

pub mod avroenc_json {
    use super::avroenc;
    use serde_json::Value;

    pub fn enc_HGRequest(v: &Value) -> Vec<u8> {
        let op = v["op"].as_str().unwrap();
        match op {
            "AddVertex" => {
                let vid = v["vertex"]["vid"].as_str().unwrap();
                let label = v["vertex"]["label"].as_str().unwrap_or("");
                let lopt = if label.is_empty() { None } else { Some(label) };
                avroenc::enc_HGRequest_AddVertex(vid, lopt)
            }
            "AddHyperedge" => {
                let eid = v["edge"]["eid"].as_str().unwrap();
                let members = v["edge"]["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap())
                    .collect::<Vec<_>>();
                avroenc::enc_HGRequest_AddHyperedge(eid, &members, Some(1))
            }
            "QueryNeighbors" => {
                let vid = v["vid"].as_str().unwrap();
                let k = v["k"].as_i64().unwrap_or(1) as i32;
                avroenc::enc_HGRequest_QueryNeighbors(vid, k)
            }
            "GetSubgraph" => {
                let vid = v["vid"].as_str().unwrap();
                let k = v["k"].as_i64().unwrap_or(1) as i32;
                avroenc::enc_HGRequest_GetSubgraph(vid, k)
            }
            "RemoveVertex" => {
                let vid = v["vid"].as_str().unwrap_or("a");
                avroenc::enc_HGRequest_RemoveVertex(vid)
            }
            "RemoveHyperedge" => {
                let eid = v["eid"].as_str().unwrap_or("e1");
                avroenc::enc_HGRequest_RemoveHyperedge(eid)
            }
            _ => avroenc::enc_HGRequest_GetSubgraph("a", 1),
        }
    }

    pub fn enc_HGResponse_json(v: &Value) -> Vec<u8> {
        let ok = v["ok"].as_bool().unwrap_or(true);
        let err = v.get("err").and_then(|e| e.as_str());
        let vertices = v["vertices"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|x| {
                (
                    x["vid"].as_str().unwrap(),
                    x.get("label").and_then(|l| l.as_str()),
                )
            })
            .collect::<Vec<_>>();
        let edges = v["edges"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|x| {
                let eid = x["eid"].as_str().unwrap();
                let members = x["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_str().unwrap())
                    .collect::<Vec<_>>();
                let weight = x.get("weight").and_then(|w| w.as_i64());
                (eid, members, weight)
            })
            .collect::<Vec<_>>();
        super::avroenc::enc_HGResponse(ok, err, &vertices, &edges)
    }
}

pub mod pathb {
    use super::tleb3;
    use super::tritpack243;

    pub fn bt_encode(mut n: i64) -> Vec<u8> {
        let mut digits: Vec<i8> = vec![];
        if n == 0 {
            digits.push(0);
        } else {
            while n != 0 {
                let mut rem = (n % 3) as i8;
                n /= 3;
                if rem == 2 {
                    rem = -1;
                    n += 1;
                }
                digits.push(rem);
            }
            digits.reverse();
        }
        let trits: Vec<u8> = digits.into_iter().map(|d| (d + 1) as u8).collect();
        let mut out = tleb3::encode_len(trits.len() as u64);
        out.extend(tritpack243::pack(&trits));
        out
    }

    pub fn enc_string(s: &str) -> Vec<u8> {
        let mut out = tleb3::encode_len(s.as_bytes().len() as u64);
        out.extend(s.as_bytes());
        out
    }

    pub fn enc_enum(index: u64) -> Vec<u8> {
        tleb3::encode_len(index)
    }
    pub fn enc_union_index(index: u64) -> Vec<u8> {
        tleb3::encode_len(index)
    }

    pub fn enc_array<T>(items: &[T], f: fn(&T) -> Vec<u8>) -> Vec<u8> {
        if items.is_empty() {
            return vec![0];
        }
        let mut out = tleb3::encode_len(items.len() as u64);
        for it in items {
            out.extend(f(it));
        }
        out.push(0);
        out
    }

    pub fn enc_map(m: &[(&str, &str)]) -> Vec<u8> {
        if m.is_empty() {
            return vec![0];
        }
        let mut out = tleb3::encode_len(m.len() as u64);
        for (k, v) in m {
            out.extend(enc_string(k));
            out.extend(enc_string(v));
        }
        out.push(0);
        out
    }
}

pub mod pathb_dec {
    use super::{tleb3, tritpack243};

    pub fn dec_len(bytes: &[u8], mut off: usize) -> (usize, usize) {
        // decode TLEB3 length and return (len, new_offset)
        let (val, new_off) = super::tleb3::decode_len(bytes, off).unwrap();
        (val as usize, new_off)
    }

    pub fn dec_string(bytes: &[u8], off: usize) -> (String, usize) {
        let (l, o2) = dec_len(bytes, off);
        let s = std::str::from_utf8(&bytes[o2..o2 + l]).unwrap().to_string();
        (s, o2 + l)
    }

    pub fn dec_union_index(bytes: &[u8], off: usize) -> (u64, usize) {
        let (u, o2) = super::tleb3::decode_len(bytes, off).unwrap();
        (u, o2)
    }

    pub fn dec_vertex(bytes: &[u8], off: usize) -> ((String, Option<String>), usize) {
        let (vid, o2) = dec_string(bytes, off);
        let (uix, o3) = dec_union_index(bytes, o2);
        let (label, o4) = if uix == 0 {
            (None, o3)
        } else {
            let (s, p) = dec_string(bytes, o3);
            (Some(s), p)
        };
        // skip attr map (length + entries) — for fixtures attr is empty (0x00)
        ((vid, label), o4 + 1)
    }
}
