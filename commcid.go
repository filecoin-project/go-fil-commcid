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
	if err := ValidateFilecoinCidSegments(mc, mh, commitment); err != nil {
		return cid.Undef, err
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
// after validating that the codec and hash type are consistent
func CIDToCommitment(c cid.Cid) ([]byte, FilMultiCodec, error) {
	decoded, err := multihash.Decode([]byte(c.Hash()))
	if err != nil {
		return nil, FC_UNDEFINED, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}

	if err := ValidateFilecoinCidSegments(
		FilMultiCodec(c.Type()),
		FilMultiHash(decoded.Code),
		decoded.Digest,
	); err != nil {
		return nil, FC_UNDEFINED, err
	}

	return decoded.Digest, FilMultiCodec(c.Type()), nil
}

// DataCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - codec: cid.FilCommitmentUnsealed
// - hash type: multihash.SHA2_256_TRUNC254_PADDED
func DataCommitmentV1ToCID(commD []byte) (cid.Cid, error) {
	return CommitmentToCID(commD, cid.FilCommitmentUnsealed, multihash.SHA2_256_TRUNC254_PADDED)
}

// CIDToDataCommitmentV1 extracts the raw data commitment from a CID
// after checking for the correct codec and hash types.
func CIDToDataCommitmentV1(c cid.Cid) ([]byte, error) {
	commD, codec, err := CIDToCommitment(c)
	if err != nil {
		return nil, err
	}
	if codec != cid.FilCommitmentUnsealed {
		return nil, ErrIncorrectCodec
	}
	return commD, nil
}

// ReplicaCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - codec: cid.FilCommitmentSealed
// - hash type: multihash.POSEIDON_BLS12_381_A1_FC1
func ReplicaCommitmentV1ToCID(commR []byte) cid.Cid {
	c, _ := CommitmentToCID(commR, cid.FilCommitmentSealed, multihash.POSEIDON_BLS12_381_A1_FC1)
	return c
}

// CIDToReplicaCommitmentV1 extracts the raw replica commitment from a CID
// after checking for the correct codec and hash types.
func CIDToReplicaCommitmentV1(c cid.Cid) ([]byte, error) {
	commR, codec, err := CIDToCommitment(c)
	if err != nil {
		return nil, err
	}
	if codec != cid.FilCommitmentSealed {
		return nil, ErrIncorrectCodec
	}
	return commR, nil
}

// ValidateFilecoinCidSegments returns an error if the provided CID parts
// conflict with each other.
func ValidateFilecoinCidSegments(mc FilMultiCodec, mh FilMultiHash, commitment []byte) error {

	switch mc {
	case cid.FilCommitmentUnsealed:
		if mh != multihash.SHA2_256_TRUNC254_PADDED {
			return ErrIncorrectHash
		}
	case cid.FilCommitmentSealed:
		if mh != multihash.POSEIDON_BLS12_381_A1_FC1 {
			return ErrIncorrectHash
		}
	default: // neigher of the codecs above: we are not in Fil teritory
		return ErrIncorrectCodec
	}

	if len(commitment) != 32 {
		return fmt.Errorf("commitments must be 32 bytes long")
	}

	return nil
}

// PieceCommitmentV1ToCID converts a commP to a CID
// -- it is just a helper function that is equivalent to
// DataCommitmentV1ToCID.
var PieceCommitmentV1ToCID = DataCommitmentV1ToCID

// CIDToPieceCommitmentV1 converts a CID to a commP
// -- it is just a helper function that is equivalent to
// CIDToDataCommitmentV1.
var CIDToPieceCommitmentV1 = CIDToDataCommitmentV1
