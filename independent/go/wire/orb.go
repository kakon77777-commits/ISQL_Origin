package wire

import "bytes"

var orbMagic=[]byte{0xd5,0x52,0x42,0x01}

type RegistryEntry struct { LocalID uint64; EntryKind Ref; PayloadKind Ref; Payload []byte }
type ORB struct { FormatVersion uint64; BundleKind Ref; Namespace Ref; Parent *Digest; Revision uint64; Entries []RegistryEntry }

func DecodeORB(data []byte)(ORB,error){
    if len(data)<4 || !bytes.Equal(data[:4],orbMagic){return ORB{},&Error{Code:"ORB_BAD_MAGIC"}}
    c:=cursor{data:data,off:4,prefix:"ORB_"}
    ver,err:=c.u(); if err!=nil{return ORB{},err}
    kind,err:=c.ref(); if err!=nil{return ORB{},err}; ns,err:=c.ref(); if err!=nil{return ORB{},err}
    present,err:=c.u(); if err!=nil{return ORB{},err}; if present>1{return ORB{},&Error{Code:"ORB_PARENT_FLAG_INVALID"}}
    var parent *Digest
    if present==1 { d,err:=c.digest(); if err!=nil{return ORB{},err}; parent=&d }
    rev,err:=c.u(); if err!=nil{return ORB{},err}; count,err:=c.u(); if err!=nil{return ORB{},err}
    entries:=make([]RegistryEntry,0,count); var prev uint64
    for i:=uint64(0);i<count;i++{
        id,err:=c.u();if err!=nil{return ORB{},err}; if i>0 && id<=prev{return ORB{},&Error{Code:"ORB_ENTRY_ORDER"}}; prev=id
        ek,err:=c.ref();if err!=nil{return ORB{},err};pk,err:=c.ref();if err!=nil{return ORB{},err};p,err:=c.bytes();if err!=nil{return ORB{},err}
        entries=append(entries,RegistryEntry{id,ek,pk,p})
    }
    if c.off!=len(data){return ORB{},&Error{Code:"ORB_TRAILING_BYTES"}}
    return ORB{ver,kind,ns,parent,rev,entries},nil
}
