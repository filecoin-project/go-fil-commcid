package commcid

import (
	"errors"
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"golang.org/x/xerrors"
)

type FilMultiCodec uint64
type FilMultiHash uint64

// FC_UNDEFINED is just a signifier for no codec determined
const FC_UNDEFINED = FilMultiCodec(0)

var (
	// ErrIncorrectCodec means the codec for a CID is a block format that does not match
	// a commitment hash
	ErrIncorrectCodec = errors.New("unexpected commitment codec")
	// ErrIncorrectHash means the hash function for this CID does not match the expected
	// hash for this type of commitment
	ErrIncorrectHash = errors.New("incorrect hashing function for data commitment")
)

// CommitmentToCID converts a raw commitment hash to a CID
// by adding:
// - the given filecoin codec type
// - the given filecoin hash type
func CommitmentToCID(commitment []byte, mc FilMultiCodec, mh FilMultiHash) (cid.Cid, error) {
	if len(commitment) != 32 {
		return cid.Undef, fmt.Errorf("commitments must be 32 bytes long")
	} else if !ValidFilecoinMultihash(uint64(mh)) {
		return cid.Undef, ErrIncorrectHash
	} else if !ValidFilecoinCodec(uint64(mc)) {
		return cid.Undef, ErrIncorrectCodec
	}

	mhBuf := make(
		[]byte,
		(varint.UvarintSize(uint64(mh)) + varint.UvarintSize(uint64(len(commitment))) + len(commitment)),
	)

	pos := varint.PutUvarint(mhBuf, uint64(mh))
	pos += varint.PutUvarint(mhBuf[pos:], uint64(len(commitment)))
	copy(mhBuf[pos:], commitment)

	return cid.NewCidV1(uint64(mc), multihash.Multihash(mhBuf)), nil
}

// CIDToCommitment extracts the raw data commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToCommitment(c cid.Cid) ([]byte, FilMultiCodec, error) {
	if !ValidFilecoinCodec(c.Type()) {
		return nil, FC_UNDEFINED, ErrIncorrectCodec
	}
	decoded, err := multihash.Decode([]byte(c.Hash()))
	if err != nil {
		return nil, FC_UNDEFINED, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}
	if !ValidFilecoinMultihash(decoded.Code) {
		return nil, FC_UNDEFINED, ErrIncorrectHash
	}
	return decoded.Digest, FilMultiCodec(c.Type()), nil
}

// DataCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - codec of type FC_UNSEALED_V1
// - hashing type of FC_SHA2_256_TRUNC254
func DataCommitmentV1ToCID(commD []byte) (cid.Cid, error) {
	return CommitmentToCID(commD, cid.FilCommitmentUnsealed, multihash.SHA2_256_TRUNC254_PADDED)
}

// CIDToDataCommitmentV1 extracts the raw data commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToDataCommitmentV1(c cid.Cid) ([]byte, error) {
	commD, hash, err := CIDToCommitment(c)
	if err != nil {
		return nil, err
	}
	if hash != cid.FilCommitmentUnsealed {
		return nil, ErrIncorrectHash
	}
	return commD, nil
}

// ReplicaCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - codec of type FC_SEALED_V1
// - hashing type of FC_SHA2_256_TRUNC254
func ReplicaCommitmentV1ToCID(commR []byte) cid.Cid {
	c, _ := CommitmentToCID(commR, cid.FilCommitmentSealed, multihash.SHA2_256_TRUNC254_PADDED)
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
	if hash != cid.FilCommitmentSealed {
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

// ValidFilecoinCodec returns true if the given multicodec type
// is recognized as belonging to filecoin
func ValidFilecoinCodec(mc uint64) bool {
	return mc == cid.FilCommitmentUnsealed || mc == cid.FilCommitmentSealed
}

// ValidFilecoinMultihash returns true if the given multihash type
// is recognized as belonging to filecoin
func ValidFilecoinMultihash(mh uint64) bool {
	return mh == multihash.SHA2_256_TRUNC254_PADDED // sha2-256-trunc2 is all we support for now
}
