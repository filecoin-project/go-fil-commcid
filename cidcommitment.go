package cidcommitment

import (
	"errors"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"golang.org/x/xerrors"
)

const (
	FC_HASH_UNSEALED = 0xfc1
	FC_HASH_SEALED   = 0xfc2
)

var (
	// ErrIncorrectCodec means the codec for a CID is a block format that does not match
	// a commitment hash
	ErrIncorrectCodec = errors.New("codec for all commitments is raw")
	// ErrIncorrectHash means the hash function for this CID does not match the expected
	// hash for this type of commitment
	ErrIncorrectHash = errors.New("incorrect hashing function for data commitment")
)

// DataCommitmentToCID converts a raw data commitment to a CID
// by adding:
// - serialization type of raw
// - hashing type of reserved Filecoin reserved unsealed hashing function (0xfc1)
func DataCommitmentToCID(commD []byte) cid.Cid {
	mh := rawMultiHash(FC_HASH_UNSEALED, commD)
	return cid.NewCidV1(cid.Raw, mh)
}

// CIDToDataCommitment extracts the raw data commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToDataCommitment(c cid.Cid) ([]byte, error) {
	if c.Type() != cid.Raw {
		return nil, ErrIncorrectCodec
	}
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	if err != nil {
		return nil, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}
	if decoded.Code != FC_HASH_UNSEALED {
		return nil, ErrIncorrectHash
	}
	return decoded.Digest, nil
}

// ReplicaCommitmentToCID converts a raw data commitment to a CID
// by adding:
// - serialization type of raw
// - hashing type of reserved Filecoin reserved sealed hashing function (0xfc2)
func ReplicaCommitmentToCID(commR []byte) cid.Cid {
	mh := rawMultiHash(FC_HASH_SEALED, commR)
	return cid.NewCidV1(cid.Raw, mh)
}

// CIDToReplicaCommitment extracts the raw replica commitment from a CID
// assuming that it has the correct hashing function and
// serialization types
func CIDToReplicaCommitment(c cid.Cid) ([]byte, error) {
	if c.Type() != cid.Raw {
		return nil, ErrIncorrectCodec
	}
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	if err != nil {
		return nil, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}
	if decoded.Code != FC_HASH_SEALED {
		return nil, ErrIncorrectHash
	}
	return decoded.Digest, nil
}

// PieceCommitmentToCID converts a commP to a CID
// -- it is just a helper function that is equivalent to
// DataCommitmentToCID.
func PieceCommitmentToCID(commP []byte) cid.Cid {
	return DataCommitmentToCID(commP)
}

// CIDToPieceCommitment converts a CID to a commP
// -- it is just a helper function that is equivalent to
// CIDToDataCommitment.
func CIDToPieceCommitment(c cid.Cid) ([]byte, error) {
	return CIDToDataCommitment(c)
}

func rawMultiHash(code uint64, buf []byte) multihash.Multihash {
	newBuf := make([]byte, varint.UvarintSize(code)+varint.UvarintSize(uint64(len(buf)))+len(buf))
	n := varint.PutUvarint(newBuf, code)
	n += varint.PutUvarint(newBuf[n:], uint64(len(buf)))

	copy(newBuf[n:], buf)
	return multihash.Multihash(newBuf)
}
