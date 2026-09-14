package wire

type cursor struct { data []byte; off int; prefix string }
func (c *cursor) remaining() int { return len(c.data)-c.off }
func (c *cursor) u() (uint64,error) {
    v,n,err:=DecodeUVarInt(c.data[c.off:])
    if err!=nil {
        if e,ok:=err.(*Error); ok && e.Code=="NON_CANONICAL_VARINT" { return 0,&Error{Code:c.prefix+"NON_CANONICAL_VARINT"} }
        return 0,&Error{Code:c.prefix+"TRUNCATED"}
    }
    c.off+=n; return v,nil
}
func (c *cursor) ref()(Ref,error){
    a,err:=c.u(); if err!=nil{return Ref{},err}; b,err:=c.u(); if err!=nil{return Ref{},err}; return Ref{a,b},nil
}
func (c *cursor) bytes()([]byte,error){
    n,err:=c.u(); if err!=nil{return nil,err}; if n>uint64(c.remaining()){return nil,&Error{Code:c.prefix+"TRUNCATED"}}
    b:=append([]byte(nil),c.data[c.off:c.off+int(n)]...); c.off+=int(n); return b,nil
}
func (c *cursor) digest()(Digest,error){r,err:=c.ref();if err!=nil{return Digest{},err};b,err:=c.bytes();if err!=nil{return Digest{},err};return Digest{r,b},nil}
