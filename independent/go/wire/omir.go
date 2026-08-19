package wire

import "bytes"

var omirMagic=[]byte{0xd5,0x49,0x4f,0x01}

type RegistryPin struct { Slot uint64; RegistryKind Ref; Revision uint64; Digest Digest; Flags uint64 }
type Section struct { Tag uint64; Flags uint64; Payload []byte }
type OMIR struct { FormatVersion uint64; CriticalFlags uint64; ObjectKind Ref; Profile Ref; HashPolicy Ref; RegistryPins []RegistryPin; Sections []Section }

func DecodeOMIR(data []byte)(OMIR,error){
    if len(data)<4 || !bytes.Equal(data[:4],omirMagic){return OMIR{},&Error{Code:"OMIR_BAD_MAGIC"}}
    c:=cursor{data:data,off:4,prefix:"OMIR_"}
    ver,err:=c.u();if err!=nil{return OMIR{},err}; flags,err:=c.u();if err!=nil{return OMIR{},err}
    obj,err:=c.ref();if err!=nil{return OMIR{},err};prof,err:=c.ref();if err!=nil{return OMIR{},err};hash,err:=c.ref();if err!=nil{return OMIR{},err}
    pc,err:=c.u();if err!=nil{return OMIR{},err}; pins:=make([]RegistryPin,0,pc);var prevSlot uint64
    for i:=uint64(0);i<pc;i++{slot,err:=c.u();if err!=nil{return OMIR{},err};if i>0&&slot<=prevSlot{return OMIR{},&Error{Code:"OMIR_REGISTRY_SLOT_ORDER"}};prevSlot=slot
        kind,err:=c.ref();if err!=nil{return OMIR{},err};rev,err:=c.u();if err!=nil{return OMIR{},err};d,err:=c.digest();if err!=nil{return OMIR{},err};pf,err:=c.u();if err!=nil{return OMIR{},err};pins=append(pins,RegistryPin{slot,kind,rev,d,pf})}
    sc,err:=c.u();if err!=nil{return OMIR{},err};secs:=make([]Section,0,sc);var prevTag uint64
    for i:=uint64(0);i<sc;i++{tag,err:=c.u();if err!=nil{return OMIR{},err};if i>0&&tag<=prevTag{return OMIR{},&Error{Code:"OMIR_SECTION_ORDER"}};prevTag=tag
        sf,err:=c.u();if err!=nil{return OMIR{},err};payload,err:=c.bytes();if err!=nil{return OMIR{},err}
        if tag>12 && sf&1==1{return OMIR{},&Error{Code:"OMIR_UNKNOWN_CRITICAL_SECTION"}}
        secs=append(secs,Section{tag,sf,payload})}
    if c.off!=len(data){return OMIR{},&Error{Code:"OMIR_TRAILING_BYTES"}}
    return OMIR{ver,flags,obj,prof,hash,pins,secs},nil
}
