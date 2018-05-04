package filesystem

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"upspin.io/config"
	"upspin.io/factotum"
	"upspin.io/pack"
	"upspin.io/test/testutil"
	"upspin.io/upspin"
)

func TestPack(t *testing.T) {
	const (
		user upspin.UserName = "joe@upspin.io"
		name                 = upspin.PathName(user + "/file/of/user")
		text                 = "this is some text"
	)
	cfg, packer := setup(user)

	// First pack.
	d := &upspin.DirEntry{
		Name:       name,
		SignedName: name,
		Writer:     cfg.UserName(),
	}
	simplePack(cfg, d)

	// Now unpack.
	clear := unpackBlob(t, cfg, packer, d, []byte(text))

	if !bytes.Equal([]byte(text), clear) {
		t.Errorf("text: expected %q; got %q", text, clear)
	}
	if d.SignedName != d.Name {
		t.Errorf("SignedName: expected %q; got %q", d.Name, d.SignedName)
	}

}

// unpackBlob unpacks cipher according to the parameters and returns the plain text.
func unpackBlob(t *testing.T, cfg upspin.Config, packer upspin.Packer, d *upspin.DirEntry, cipher []byte) []byte {
	bp, err := packer.Unpack(cfg, d)
	if err != nil {
		t.Fatal("unpackBlob:", err)
	}
	if _, ok := bp.NextBlock(); !ok {
		t.Fatal("unpackBlob: no next block")
	}
	text, err := bp.Unpack(cipher)
	if err != nil {
		t.Fatal("unpackBlob:", err)
	}
	return text
}

func setup(name upspin.UserName) (upspin.Config, upspin.Packer) {
	cfg := config.SetUserName(config.New(), name)
	packer := pack.Lookup(packing)
	j := strings.IndexByte(string(name), '@')
	if j < 0 {
		log.Fatalf("malformed username %s", name)
	}
	f, err := factotum.NewFromDir(testutil.Repo("key", "testdata", string(name[:j])))
	if err != nil {
		log.Fatalf("unable to initialize factotum for %s", string(name[:j]))
	}
	cfg = config.SetFactotum(cfg, f)
	return cfg, packer
}
