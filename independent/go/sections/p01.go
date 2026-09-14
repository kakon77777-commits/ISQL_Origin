package sections

import (
    "fmt"
    "github.com/kakon77777-commits/isql-origin-go/wire"
)

type Error struct{ Code string }
func (e *Error) Error() string{return e.Code}

type cur struct{ d []byte; i int }
func (c *cur) u()(uint64,error){v,n,e:=wire.DecodeUVarInt(c.d[c.i:]);if e!=nil{return 0,e};c.i+=n;return v,nil}
func (c *cur) ref()(wire.Ref,error){a,e:=c.u();if e!=nil{return wire.Ref{},e};b,e:=c.u();if e!=nil{return wire.Ref{},e};return wire.Ref{BundleSlot:a,LocalID:b},nil}
func (c *cur) bytes()([]byte,error){n,e:=c.u();if e!=nil{return nil,e};if n>uint64(len(c.d)-c.i){return nil,&Error{"SECTION_TRUNCATED"}};b:=append([]byte(nil),c.d[c.i:c.i+int(n)]...);c.i+=int(n);return b,nil}
func (c *cur) done()error{if c.i!=len(c.d){return &Error{"SECTION_TRAILING_BYTES"}};return nil}
func refLess(a,b wire.Ref)bool{if a.BundleSlot!=b.BundleSlot{return a.BundleSlot<b.BundleSlot};return a.LocalID<b.LocalID}
func refs(c *cur)([]wire.Ref,error){n,e:=c.u();if e!=nil{return nil,e};out:=make([]wire.Ref,0,n);var prev wire.Ref;for i:=uint64(0);i<n;i++{r,e:=c.ref();if e!=nil{return nil,e};if i>0&&!refLess(prev,r){return nil,&Error{"SECTION_REF_LIST_NOT_CANONICAL"}};prev=r;out=append(out,r)};return out,nil}

type IdentityEntry struct{ Kind,Algorithm wire.Ref; Digest []byte; ScopeFlags uint64; Authority,Provenance *wire.Ref }
type InvariantContract struct{ Invariant wire.Ref; Observables []wire.Ref; Comparator wire.Ref; Tolerance *wire.Ref; Scope,Validator wire.Ref; Severity uint64 }
type PayloadEntry struct{ Payload wire.Ref; StorageClass uint64; MediaType,Codec wire.Ref; LogicalLength uint64; Digest wire.Digest; Body []byte }
type ProfileBinding struct{ Profile wire.Ref; Version uint64; ObjectKinds []wire.Ref; RequiredSections,OptionalSections []uint64; IdentityPolicy,Canonicalization,DecoderContract wire.Ref; BridgeContracts []wire.Ref; ConformanceClass wire.Ref }

func DecodeIdentityFamily(d []byte)([]IdentityEntry,error){c:=cur{d:d};n,e:=c.u();if e!=nil{return nil,e};out:=make([]IdentityEntry,0,n);var prev wire.Ref
    for i:=uint64(0);i<n;i++{kind,e:=c.ref();if e!=nil{return nil,e};if i>0&&!refLess(prev,kind){return nil,&Error{"IDENTITY_ORDER"}};prev=kind;alg,e:=c.ref();if e!=nil{return nil,e};dig,e:=c.bytes();if e!=nil{return nil,e};sf,e:=c.u();if e!=nil{return nil,e};mask,e:=c.u();if e!=nil{return nil,e};if mask&^uint64(3)!=0{return nil,&Error{"IDENTITY_OPTION_MASK_INVALID"}};var a,p *wire.Ref;if mask&1!=0{r,e:=c.ref();if e!=nil{return nil,e};a=&r};if mask&2!=0{r,e:=c.ref();if e!=nil{return nil,e};p=&r};out=append(out,IdentityEntry{kind,alg,dig,sf,a,p})}
    if e:=c.done();e!=nil{return nil,e};return out,nil}

func DecodeInvariantContracts(d []byte)([]InvariantContract,error){c:=cur{d:d};n,e:=c.u();if e!=nil{return nil,e};out:=make([]InvariantContract,0,n);var prev wire.Ref
    for i:=uint64(0);i<n;i++{inv,e:=c.ref();if e!=nil{return nil,e};if i>0&&!refLess(prev,inv){return nil,&Error{"INVARIANT_ORDER"}};prev=inv;obs,e:=refs(&c);if e!=nil{return nil,e};cmp,e:=c.ref();if e!=nil{return nil,e};present,e:=c.u();if e!=nil{return nil,e};if present>1{return nil,&Error{"INVARIANT_TOLERANCE_FLAG_INVALID"}};var tol *wire.Ref;if present==1{r,e:=c.ref();if e!=nil{return nil,e};tol=&r};scope,e:=c.ref();if e!=nil{return nil,e};val,e:=c.ref();if e!=nil{return nil,e};sev,e:=c.u();if e!=nil{return nil,e};out=append(out,InvariantContract{inv,obs,cmp,tol,scope,val,sev})}
    if e:=c.done();e!=nil{return nil,e};return out,nil}

func DecodePayloadTable(d []byte)([]PayloadEntry,error){c:=cur{d:d};n,e:=c.u();if e!=nil{return nil,e};out:=make([]PayloadEntry,0,n);var prev wire.Ref
    for i:=uint64(0);i<n;i++{pr,e:=c.ref();if e!=nil{return nil,e};if i>0&&!refLess(prev,pr){return nil,&Error{"PAYLOAD_ORDER"}};prev=pr;sc,e:=c.u();if e!=nil{return nil,e};mt,e:=c.ref();if e!=nil{return nil,e};codec,e:=c.ref();if e!=nil{return nil,e};ll,e:=c.u();if e!=nil{return nil,e};alg,e:=c.ref();if e!=nil{return nil,e};db,e:=c.bytes();if e!=nil{return nil,e};body,e:=c.bytes();if e!=nil{return nil,e};out=append(out,PayloadEntry{pr,sc,mt,codec,ll,wire.Digest{Algorithm:alg,Bytes:db},body})}
    if e:=c.done();e!=nil{return nil,e};return out,nil}

func uintList(c *cur)([]uint64,error){n,e:=c.u();if e!=nil{return nil,e};out:=make([]uint64,0,n);var prev uint64;for i:=uint64(0);i<n;i++{v,e:=c.u();if e!=nil{return nil,e};if i>0&&v<=prev{return nil,&Error{"UINT_LIST_NOT_CANONICAL"}};prev=v;out=append(out,v)};return out,nil}
func DecodeProfileBinding(d []byte)(ProfileBinding,error){c:=cur{d:d};p,e:=c.ref();if e!=nil{return ProfileBinding{},e};ver,e:=c.u();if e!=nil{return ProfileBinding{},e};oks,e:=refs(&c);if e!=nil{return ProfileBinding{},e};req,e:=uintList(&c);if e!=nil{return ProfileBinding{},e};opt,e:=uintList(&c);if e!=nil{return ProfileBinding{},e};ip,e:=c.ref();if e!=nil{return ProfileBinding{},e};can,e:=c.ref();if e!=nil{return ProfileBinding{},e};dec,e:=c.ref();if e!=nil{return ProfileBinding{},e};bridges,e:=refs(&c);if e!=nil{return ProfileBinding{},e};cc,e:=c.ref();if e!=nil{return ProfileBinding{},e};if e:=c.done();e!=nil{return ProfileBinding{},e};return ProfileBinding{p,ver,oks,req,opt,ip,can,dec,bridges,cc},nil}

func DebugRef(r wire.Ref)string{return fmt.Sprintf("%d:%d",r.BundleSlot,r.LocalID)}
