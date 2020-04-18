package commcid

import (
	"errors"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"golang.org/x/xerrors"
)

// FilecoinMultihashCode is a multicodec index that identifiesh a multihash
// type for Filecoin
type FilecoinMultihashCode uint64

const (
	// FC_UNSEALED_V1 is the v1 hashing algorithm used in
	// constructing merkleproofs of unsealed data
	FC_UNSEALED_V1 FilecoinMultihashCode = 0xfc1 + iota

	// FC_SEALED_V1 is the v1 hashing algorithm used in
	// constructing merkleproofs of sealed replicated data
	FC_SEALED_V1

	// FC_RESERVED3 is reserved for future use
	FC_RESERVED3

	// FC_RESERVED4 is reserved for future use
	FC_RESERVED4

	// FC_RESERVED5 is reserved for future use
	FC_RESERVED5

	// FC_RESERVED6 is reserved for future use
	FC_RESERVED6

	// FC_RESERVED7 is reserved for future use
	FC_RESERVED7

	// FC_RESERVED8 is reserved for future use
	FC_RESERVED8

	// FC_RESERVED9 is reserved for future use
	FC_RESERVED9

	// FC_RESERVED10 is reserved for future use
	FC_RESERVED10
)

// FilecoinMultihashNames maps filecoin multihash codes to a text descriptions
var FilecoinMultihashNames = map[FilecoinMultihashCode]string{
	FC_UNSEALED_V1: "Filecoin Merkleproof Of Unsealed Data, V1",
	FC_SEALED_V1:   "Filecoin Merkleproof Of Sealed Data, V1",
	FC_RESERVED3:   "Reserved",
	FC_RESERVED4:   "Reserved",
	FC_RESERVED5:   "Reserved",
	FC_RESERVED6:   "Reserved",
	FC_RESERVED7:   "Reserved",
	FC_RESERVED8:   "Reserved",
	FC_RESERVED9:   "Reserved",
	FC_RESERVED10:  "Reserved",
}

// FC_UNDEFINED is just a signifier for no hash type determined
const FC_UNDEFINED = FilecoinMultihashCode(0)

// FilecoinCodecType is the serialization type for a Commitment CID
// = always just raw for now
const FilecoinCodecType = cid.Raw

var (
	// ErrIncorrectCodec means the codec for a CID is a block format that does not match
	// a commitment hash
	ErrIncorrectCodec = errors.New("codec for all commitments is raw")
	// ErrIncorrectHash means the hash function for this CID does not match the expected
	// hash for this type of commitment
	ErrIncorrectHash = errors.New("incorrect hashing function for data commitment")
)

// CommitmentToCID converts a raw commitment hash to a CID
// by adding:
// - serialization type of raw
// - the given filecoin hash type
func CommitmentToCID(commitment []byte, code FilecoinMultihashCode) (cid.Cid, error) {
	if len(commitment) != 32 {
		return cid.Undef, fmt.Errorf("commitments must be 32 bytes long")
	}

	if !ValidFilecoinMultihash(code) {
		return cid.Undef, ErrIncorrectHash
	}
	mh := rawMultiHash(uint64(code), commitment)
	return cid.NewCidV1(FilecoinCodecType, mh), nil
}

// CIDToCommitment extracts the raw data commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToCommitment(c cid.Cid) ([]byte, FilecoinMultihashCode, error) {
	if c.Type() != FilecoinCodecType {
		return nil, FC_UNDEFINED, ErrIncorrectCodec
	}
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	if err != nil {
		return nil, FC_UNDEFINED, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}
	code := FilecoinMultihashCode(decoded.Code)
	if !ValidFilecoinMultihash(code) {
		return nil, FC_UNDEFINED, ErrIncorrectHash
	}
	return decoded.Digest, code, nil
}

// DataCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - serialization type of raw
// - hashing type of Filecoin unsealed hashing function v1 (0xfc2)
func DataCommitmentV1ToCID(commD []byte) (cid.Cid, error) {
	return CommitmentToCID(commD, FC_UNSEALED_V1)
}

// CIDToDataCommitmentV1 extracts the raw data commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToDataCommitmentV1(c cid.Cid) ([]byte, error) {
	commD, hash, err := CIDToCommitment(c)
	if err != nil {
		return nil, err
	}
	if hash != FC_UNSEALED_V1 {
		return nil, ErrIncorrectHash
	}
	return commD, nil
}

// ReplicaCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - serialization type of raw
// - hashing type of Filecoin sealed hashing function v1 (0xfc2)
func ReplicaCommitmentV1ToCID(commR []byte) cid.Cid {
	c, _ := CommitmentToCID(commR, FC_SEALED_V1)
	return c
}

// CIDToReplicaCommitmentV1 extracts the raw replica commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToReplicaCommitmentV1(c cid.Cid) ([]byte, error) {
	commR, hash, err := CIDToCommitment(c)
	if err != nil {
		return nil, err
	}
	if hash != FC_SEALED_V1 {
		return nil, ErrIncorrectHash
	}
	return commR, nil
}

// PieceCommitmentV1ToCID converts a commP to a CID
// -- it is just a helper function that is equivalent to
// DataCommitmentV1ToCID.
func PieceCommitmentV1ToCID(commP []byte) (cid.Cid, error) {
	return DataCommitmentV1ToCID(commP)
}

// CIDToPieceCommitmentV1 converts a CID to a commP
// -- it is just a helper function that is equivalent to
// CIDToDataCommitmentV1.
func CIDToPieceCommitmentV1(c cid.Cid) ([]byte, error) {
	return CIDToDataCommitmentV1(c)
}

func rawMultiHash(code uint64, buf []byte) multihash.Multihash {
	newBuf := make([]byte, varint.UvarintSize(code)+varint.UvarintSize(uint64(len(buf)))+len(buf))
	n := varint.PutUvarint(newBuf, code)
	n += varint.PutUvarint(newBuf[n:], uint64(len(buf)))

	copy(newBuf[n:], buf)
	return multihash.Multihash(newBuf)
}

// ValidFilecoinMultihash returns true if the given multihash type
// is recognized as belonging to filecoin
func ValidFilecoinMultihash(code FilecoinMultihashCode) bool {
	_, ok := FilecoinMultihashNames[code]
	return ok
}
