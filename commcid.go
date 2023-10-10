// Package commcid provides helpers to convert between Piece/Data/Replica
// Commitments and their CID representation
package commcid

import (
	"errors"
	"fmt"
	"math/bits"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"golang.org/x/xerrors"
)

// FilMultiCodec is a uint64-sized type representing a Filecoin-specific codec
type FilMultiCodec uint64

// FilMultiHash is a uint64-sized type representing a Filecoin-specific multihash
type FilMultiHash uint64

// FILCODEC_UNDEFINED is just a signifier for "no codec determined
const FILCODEC_UNDEFINED = FilMultiCodec(0)

// FILMULTIHASH_UNDEFINED is a signifier for "no multihash etermined"
const FILMULTIHASH_UNDEFINED = FilMultiHash(0)

const FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE = 0x1011

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
// Deprecated: Use the alternatives like ReplicaCommitmentV1ToCID, DataCommitmentV1ToCID or DataCommitmentV1ToCID
func CommitmentToCID(mc FilMultiCodec, mh FilMultiHash, commX []byte) (cid.Cid, error) {
	if err := validateFilecoinCidSegments(mc, mh, commX); err != nil {
		return cid.Undef, err
	}

	mhBuf := make(
		[]byte,
		(varint.UvarintSize(uint64(mh)) + varint.UvarintSize(uint64(len(commX))) + len(commX)),
	)

	pos := varint.PutUvarint(mhBuf, uint64(mh))
	pos += varint.PutUvarint(mhBuf[pos:], uint64(len(commX)))
	copy(mhBuf[pos:], commX)

	return cid.NewCidV1(uint64(mc), multihash.Multihash(mhBuf)), nil
}

// CIDToCommitment extracts the raw commitment bytes, the FilMultiCodec and
// FilMultiHash from a CID, after validating that the codec and hash type are
// consistent
//
// Deprecated: Use the alternatives like CIDToReplicaCommitmentV1, CIDToDataCommitmentV1 or PieceMhCIDToDataCommitmentV1
func CIDToCommitment(c cid.Cid) (FilMultiCodec, FilMultiHash, []byte, error) {
	decoded, err := multihash.Decode([]byte(c.Hash()))
	if err != nil {
		return FILCODEC_UNDEFINED, FILMULTIHASH_UNDEFINED, nil, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}

	filCodec := FilMultiCodec(c.Type())
	filMh := FilMultiHash(decoded.Code)
	if err := validateFilecoinCidSegments(filCodec, filMh, decoded.Digest); err != nil {
		return FILCODEC_UNDEFINED, FILMULTIHASH_UNDEFINED, nil, err
	}

	return filCodec, filMh, decoded.Digest, nil
}

// DataCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - codec: cid.FilCommitmentUnsealed
// - hash type: multihash.SHA2_256_TRUNC254_PADDED
//
// Deprecated: This function should be avoided when possible and DataCommitmentV1ToPieceMhCID preferred
func DataCommitmentV1ToCID(commD []byte) (cid.Cid, error) {
	return CommitmentToCID(cid.FilCommitmentUnsealed, multihash.SHA2_256_TRUNC254_PADDED, commD)
}

// Fr32PaddedSizeToV1TreeHeight calculates the height of the piece tree given data that's been FR32 padded. Because
// pieces are only defined on binary trees if the size is not a power of 2 it will be rounded up to the next one under
// the assumption that the rest of the tree will be padded out (e.g. with zeros)
func Fr32PaddedSizeToV1TreeHeight(size uint64) uint8 {
	if size <= 32 {
		return 0
	}

	// Calculate the floor of log2(size)
	b := 63 - bits.LeadingZeros64(size)
	// Leaf size is 32 == 2^5
	b -= 5

	// Check if the size is a power of 2 and if not then add one since the tree will need to be padded out
	if 32<<b < size {
		b += 1
	}
	return uint8(b)
}

// UnpaddedSizeToV1TreeHeight calculates the height of the piece tree given the data that's meant to be encoded in the
// tree before any FR32 padding is applied. Because pieces are only defined on binary trees of FR32 encoded data if the
// size is not a power of 2 after the FR32 padding is applied it will be rounded up to the next one under the assumption
// that the rest of the tree will be padded out (e.g. with zeros)
func UnpaddedSizeToV1TreeHeight(size uint64) (uint8, error) {
	if size*128 < size {
		return 0, fmt.Errorf("unsupported size: too big")
	}

	paddedSize := size * 128 / 127
	if paddedSize*127 != size*128 {
		paddedSize += 1
	}

	return Fr32PaddedSizeToV1TreeHeight(paddedSize), nil
}

// UnpaddedSizeToV1TreeHeightAndPadding calculates the height of the piece tree given the data that's meant to be
// encoded in the tree before any FR32 padding is applied. Because pieces are only defined on binary trees of FR32
// encoded data if the size is not a power of 2 after the FR32 padding is applied it will be rounded up to the next one
// under the assumption that the rest of the tree will be padded out (e.g. with zeros). The amount of data padding that
// is needed to be applied is returned alongside the tree height.
func UnpaddedSizeToV1TreeHeightAndPadding(dataSize uint64) (uint8, uint64, error) {
	if dataSize*128 < dataSize {
		return 0, 0, fmt.Errorf("unsupported size: too big")
	}

	if dataSize < 127 {
		return 0, 0, fmt.Errorf("unsupported size: too small")
	}

	fr32DataSize := dataSize * 128 / 127
	// If the FR32 padding doesn't fill an exact number of bytes add up to 1 more byte of zeros to round it out
	if fr32DataSize*127 != dataSize*128 {
		fr32DataSize += 1
	}

	treeHeight := Fr32PaddedSizeToV1TreeHeight(fr32DataSize)
	paddedFr32DataSize := uint64(32) << treeHeight
	paddedDataSize := paddedFr32DataSize / 128 * 127
	padding := paddedDataSize - dataSize

	return treeHeight, padding, nil
}

// DataCommitmentV1ToPieceMhCID converts a raw data commitment and the height of the commitment tree
// (i.e. log_2(padded data size in bytes) - 5, because 2^5 is 32 bytes which is the leaf node size) to a CID
// by adding:
// - codec: cid.Raw
// - hash type: multihash.SHA2_256_TRUNC254_PADDED_BINARY_TREE
//
// The helpers UnpaddedSizeToV1TreeHeight and Fr32PaddedSizeToV1TreeHeight may help in computing tree height
func DataCommitmentV1ToPieceMhCID(commD []byte, unpaddedDataSize uint64) (cid.Cid, error) {
	if len(commD) != 32 {
		return cid.Undef, fmt.Errorf("commitments must be 32 bytes long")
	}

	if unpaddedDataSize < 127 {
		return cid.Undef, fmt.Errorf("unpadded data size must be at least 127, but was %d", unpaddedDataSize)
	}

	height, padding, err := UnpaddedSizeToV1TreeHeightAndPadding(unpaddedDataSize)
	if err != nil {
		return cid.Undef, err
	}

	if padding > varint.MaxValueUvarint63 {
		return cid.Undef, fmt.Errorf("padded data size must be less than 2^63-1, but was %d", padding)
	}

	mh := FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE
	paddingSize := varint.UvarintSize(padding)
	digestSize := len(commD) + 1 + paddingSize

	mhBuf := make(
		[]byte,
		varint.UvarintSize(uint64(mh))+varint.UvarintSize(uint64(digestSize))+digestSize,
	)

	pos := varint.PutUvarint(mhBuf, uint64(mh))
	pos += varint.PutUvarint(mhBuf[pos:], uint64(digestSize))
	pos += varint.PutUvarint(mhBuf[pos:], padding)
	mhBuf[pos] = height
	pos++
	copy(mhBuf[pos:], commD)

	return cid.NewCidV1(uint64(cid.Raw), mhBuf), nil
}

// CIDToDataCommitmentV1 extracts the raw data commitment from a CID
// after checking for the correct codec and hash types.
//
// Deprecated: This function should be avoided when possible and PieceMhCIDToDataCommitmentV1 preferred
func CIDToDataCommitmentV1(c cid.Cid) ([]byte, error) {
	codec, _, commD, err := CIDToCommitment(c)
	if err != nil {
		return nil, err
	}
	if codec != cid.FilCommitmentUnsealed {
		return nil, ErrIncorrectCodec
	}
	return commD, nil
}

// PieceMhCIDToDataCommitmentV1 extracts the raw data commitment and unpadded data size from the CID
func PieceMhCIDToDataCommitmentV1(c cid.Cid) ([]byte, uint64, error) {
	decoded, err := multihash.Decode(c.Hash())
	if err != nil {
		return nil, 0, xerrors.Errorf("Error decoding data commitment hash: %w", err)
	}

	if decoded.Code != FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE {
		return nil, 0, ErrIncorrectHash
	}

	if decoded.Length < 34 {
		return nil, 0, xerrors.Errorf("expected multihash digest to be at least 34 bytes, but was %d bytes", decoded.Length)
	}

	paddingSize, paddingSizeVarintLen, err := varint.FromUvarint(decoded.Digest)
	if err != nil {
		return nil, 0, xerrors.Errorf("error decoding padding size: %w", err)
	}

	if expectedDigestSize := 33 + paddingSizeVarintLen; decoded.Length != expectedDigestSize {
		return nil, 0, xerrors.Errorf("expected multihash digest to be %d bytes, but was %d bytes", expectedDigestSize, decoded.Length)
	}

	treeHeight := decoded.Digest[paddingSizeVarintLen]

	paddedFr32TreeSize := uint64(32) << treeHeight
	paddedTreeSize := paddedFr32TreeSize * 127 / 128
	halfPaddedTreeSize := paddedTreeSize >> 1

	if paddingSize >= halfPaddedTreeSize {
		return nil, 0, xerrors.Errorf("size of padding (%d) must be less than half the size of the padded data (%d)", paddingSize, halfPaddedTreeSize)
	}

	unpaddedDataSize := paddedTreeSize - paddingSize

	if unpaddedDataSize < 127 {
		return nil, 0, fmt.Errorf("unpadded data size must be at least 127, but was %d", unpaddedDataSize)
	}

	commitmentHash := decoded.Digest[1+paddingSizeVarintLen:]
	return commitmentHash, unpaddedDataSize, nil
}

// ReplicaCommitmentV1ToCID converts a raw data commitment to a CID
// by adding:
// - codec: cid.FilCommitmentSealed
// - hash type: multihash.POSEIDON_BLS12_381_A1_FC1
func ReplicaCommitmentV1ToCID(commR []byte) (cid.Cid, error) {
	return CommitmentToCID(cid.FilCommitmentSealed, multihash.POSEIDON_BLS12_381_A1_FC1, commR)
}

// CIDToReplicaCommitmentV1 extracts the raw replica commitment from a CID
// after checking for the correct codec and hash types.
func CIDToReplicaCommitmentV1(c cid.Cid) ([]byte, error) {
	codec, _, commR, err := CIDToCommitment(c)
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
func validateFilecoinCidSegments(mc FilMultiCodec, mh FilMultiHash, commX []byte) error {

	switch mc {
	case cid.FilCommitmentUnsealed:
		if mh != multihash.SHA2_256_TRUNC254_PADDED {
			return ErrIncorrectHash
		}
	case cid.FilCommitmentSealed:
		if mh != multihash.POSEIDON_BLS12_381_A1_FC1 {
			return ErrIncorrectHash
		}
	default: // neither of the codecs above: we are not in Fil teritory
		return ErrIncorrectCodec
	}

	if len(commX) != 32 {
		return fmt.Errorf("commitments must be 32 bytes long")
	}

	return nil
}

// ConvertDataCommitmentV1V1CIDtoPieceMhCID takes a v1 piece CID and the CommP tree height and produces a
// piece multihash CID
//
// The helpers UnpaddedSizeToV1TreeHeight and Fr32PaddedSizeToV1TreeHeight may help in computing tree height
func ConvertDataCommitmentV1V1CIDtoPieceMhCID(v1PieceCid cid.Cid, unpaddedDataSize uint64) (cid.Cid, error) {
	hashDigest, err := CIDToDataCommitmentV1(v1PieceCid)
	if err != nil {
		return cid.Undef, xerrors.Errorf("Error decoding piece CID v1: %w", err)
	}

	return DataCommitmentV1ToPieceMhCID(hashDigest, unpaddedDataSize)
}

// ConvertDataCommitmentV1PieceMhCIDToV1CID takes a piece multihash CID and produces a v1 piece CID along with the
// size of the unpadded data
func ConvertDataCommitmentV1PieceMhCIDToV1CID(pieceMhCid cid.Cid) (cid.Cid, uint64, error) {
	digest, unpaddedDataSize, err := PieceMhCIDToDataCommitmentV1(pieceMhCid)
	if err != nil {
		return cid.Undef, 0, xerrors.Errorf("Error decoding data piece CID v2: %w", err)
	}

	c, err := DataCommitmentV1ToCID(digest)
	if err != nil {
		return cid.Undef, 0, xerrors.Errorf("Could not create piece CID v1: %w", err)
	}
	return c, unpaddedDataSize, nil
}

// PieceCommitmentV1ToCID converts a commP to a CID
// -- it is just a helper function that is equivalent to
// DataCommitmentV1ToCID.
//
// Deprecated: This function should be avoided when possible and DataCommitmentV1ToPieceMhCID preferred
var PieceCommitmentV1ToCID = DataCommitmentV1ToCID

// CIDToPieceCommitmentV1 converts a CID to a commP
// -- it is just a helper function that is equivalent to
// CIDToDataCommitmentV1.
//
// Deprecated: This function should be avoided when possible and PieceMhCIDToDataCommitmentV1 preferred
var CIDToPieceCommitmentV1 = CIDToDataCommitmentV1
