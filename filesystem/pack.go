package filesystem

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"upspin.io/pack/packutil"
	"upspin.io/upspin"
)

func simplePack(cfg upspin.Config, entry *upspin.DirEntry) error {
	// Compute entry signature with dkey=sum=0.
	dkey := make([]byte, aesKeyLen)
	sum := make([]byte, sha256.Size)
	sig, err := cfg.Factotum().FileSign(cfg.Factotum().DirEntryHash(entry.SignedName, entry.Link, entry.Attr, entry.Packing, entry.Time, dkey, sum))
	if err != nil {
		return err
	}

	err = pdMarshal(&entry.Packdata, sig, upspin.Signature{})
	if err != nil {
		return err
	}

	return nil
}

const (
	aesKeyLen     = 32
	marshalBufLen = 66
)

var (
	zero = big.NewInt(0)
)

func pdMarshal(dst *[]byte, sig, sig2 upspin.Signature) error {
	// sig2 is a signature with another owner key, to enable smoother key rotation.
	n := packdataLen()
	if len(*dst) < n {
		*dst = make([]byte, n)
	}
	n = 0
	n += packutil.PutBytes((*dst)[n:], sig.R.Bytes())
	n += packutil.PutBytes((*dst)[n:], sig.S.Bytes())
	if sig2.R == nil {
		sig2 = upspin.Signature{R: zero, S: zero}
	}
	n += packutil.PutBytes((*dst)[n:], sig2.R.Bytes())
	n += packutil.PutBytes((*dst)[n:], sig2.S.Bytes())
	*dst = (*dst)[:n]
	return nil
}

// packdataLen returns n big enough for packing, sig.R, sig.S
func packdataLen() int {
	return 2*marshalBufLen + binary.MaxVarintLen64 + 1
}
