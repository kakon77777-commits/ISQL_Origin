package wire

import "bytes"

func EncodeUVarInt(v uint64) []byte {
    out := make([]byte,0,10)
    for {
        b := byte(v & 0x7f); v >>= 7
        if v != 0 { b |= 0x80 }
        out = append(out,b)
        if v == 0 { return out }
    }
}

func DecodeUVarInt(data []byte) (uint64,int,error) {
    var v uint64
    for i:=0; i<10; i++ {
        if i >= len(data) { return 0,0,&Error{Code:"TRUNCATED_VARINT"} }
        b:=data[i]
        if i==9 && b>1 { return 0,0,&Error{Code:"VARINT_OVERFLOW"} }
        v |= uint64(b&0x7f) << (7*i)
        if b&0x80 == 0 {
            n:=i+1
            if !bytes.Equal(EncodeUVarInt(v), data[:n]) { return 0,0,&Error{Code:"NON_CANONICAL_VARINT"} }
            return v,n,nil
        }
    }
    return 0,0,&Error{Code:"VARINT_OVERFLOW"}
}

func EncodeRef(r Ref) []byte { out:=EncodeUVarInt(r.BundleSlot); return append(out,EncodeUVarInt(r.LocalID)...)}
func DecodeRef(data []byte)(Ref,int,error){
    a,n,err:=DecodeUVarInt(data); if err!=nil{return Ref{},0,err}
    b,m,err:=DecodeUVarInt(data[n:]); if err!=nil{return Ref{},0,err}
    return Ref{a,b},n+m,nil
}

func EncodeBytes(b []byte) []byte { out:=EncodeUVarInt(uint64(len(b))); out=append(out,b...); return out }
func DecodeBytes(data []byte)([]byte,int,error){
    n,k,err:=DecodeUVarInt(data); if err!=nil{return nil,0,err}
    if n>uint64(len(data)-k){return nil,0,&Error{Code:"TRUNCATED_BYTES"}}
    out:=append([]byte(nil),data[k:k+int(n)]...); return out,k+int(n),nil
}

func EncodeDigest(d Digest) []byte { out:=EncodeRef(d.Algorithm); out=append(out,EncodeBytes(d.Bytes)...); return out }
func DecodeDigest(data []byte)(Digest,int,error){
    r,n,err:=DecodeRef(data); if err!=nil{return Digest{},0,err}
    b,m,err:=DecodeBytes(data[n:]); if err!=nil{return Digest{},0,err}
    return Digest{Algorithm:r,Bytes:b},n+m,nil
}
