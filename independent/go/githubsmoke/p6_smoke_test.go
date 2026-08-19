package githubsmoke

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/kakon77777-commits/isql-origin-go/conformance"
    "github.com/kakon77777-commits/isql-origin-go/sidecar"
    "github.com/kakon77777-commits/isql-origin-go/wire"
)

func rootPath(parts ...string) string {
    base := []string{"..", "..", ".."}
    return filepath.Join(append(base, parts...)...)
}
func read(t *testing.T, parts ...string) []byte { t.Helper(); b,err:=os.ReadFile(rootPath(parts...)); if err!=nil{t.Fatal(err)}; return b }

func TestP6IndependentSourceSmoke(t *testing.T) {
    action := read(t,"examples","p3","valid-action.omir")
    obj,err := wire.DecodeOMIR(action); if err!=nil{t.Fatal(err)}
    if errs:=conformance.ValidateP23(obj); len(errs)!=0 { t.Fatalf("P3 validation: %v",errs) }

    mlf := read(t,"fixtures","p5","sample.mlf")
    info,err := sidecar.InspectMLF(mlf); if err!=nil{t.Fatal(err)}
    if info.Profile!="mlf-1.0" || info.Version!="1.0" || len(info.Fingerprints)!=4 { t.Fatalf("MLF info: %+v",info) }

    mem := read(t,"fixtures","p4","mem-source.isql7")
    plan,err := sidecar.ParseBridgePlan(read(t,"examples","p5","mem-to-mlf-plan.json")); if err!=nil{t.Fatal(err)}
    receipt,err := sidecar.VerifyBridge(mem,mlf,plan,read(t,"examples","p5","mem-to-mlf-observations-verified.json")); if err!=nil{t.Fatal(err)}
    if receipt.Status!="VERIFIED" || receipt.Execute || receipt.ConversionPerformed { t.Fatalf("receipt: %+v",receipt) }
}
