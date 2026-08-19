package wire

import "fmt"

type Error struct { Code string; Detail string }
func (e *Error) Error() string { if e.Detail=="" { return e.Code }; return fmt.Sprintf("%s:%s", e.Code,e.Detail) }

type Ref struct { BundleSlot uint64; LocalID uint64 }
type Digest struct { Algorithm Ref; Bytes []byte }
