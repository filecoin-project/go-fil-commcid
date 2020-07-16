package commcid_test

import (
	"bytes"
	"math/rand"
	"testing"

	commcid "github.com/filecoin-project/go-fil-commcid"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"github.com/multiformats/go-varint"
	"github.com/stretchr/testify/require"
)

func TestDataCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c, err := commcid.DataCommitmentV1ToCID(randBytes)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.FilCommitmentUnsealed))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multihash.SHA2_256_TRUNC254_PADDED))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToDataCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
			decoded, err := commcid.CIDToDataCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on non-fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := commcid.CIDToDataCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on wrong fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentSealed, testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 0))
			decoded, err := commcid.CIDToDataCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on fil hash/codec mismatch", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 0))
			decoded, err := commcid.CIDToDataCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectHash.Error())
			require.Nil(t, decoded)
		})

	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 5)
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
		decoded, err := commcid.CIDToDataCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
}

func TestReplicaCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c, err := commcid.ReplicaCommitmentV1ToCID(randBytes)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.FilCommitmentSealed))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multihash.POSEIDON_BLS12_381_A1_FC1))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToReplicaCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentSealed, hash)
			decoded, err := commcid.CIDToReplicaCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on incorrect CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := commcid.CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on non-fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := commcid.CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on wrong fil codec", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0))
			decoded, err := commcid.CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})

		t.Run("error on fil hash/codec mismatch", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentSealed, testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0))
			decoded, err := commcid.CIDToReplicaCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectHash.Error())
			require.Nil(t, decoded)
		})
	})

	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
		decoded, err := commcid.CIDToReplicaCommitmentV1(c)
		require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
		require.Nil(t, decoded)
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, testMultiHash(multihash.POSEIDON_BLS12_381_A1_FC1, randBytes, 5))
		decoded, err := commcid.CIDToReplicaCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})

}

func TestPieceCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c, err := commcid.PieceCommitmentV1ToCID(randBytes)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.FilCommitmentUnsealed))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(multihash.SHA2_256_TRUNC254_PADDED))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))

	_, err = commcid.PieceCommitmentV1ToCID(randBytes[1:])
	require.Regexp(t, "^commitments must be 32 bytes long", err.Error())
}

func TestCIDToPieceCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
			decoded, err := commcid.CIDToPieceCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on incorrect CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := commcid.CIDToPieceCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes, 5)
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, hash)
		decoded, err := commcid.CIDToPieceCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.FilCommitmentUnsealed, multihash.Multihash(encoded))
		decoded, err := commcid.CIDToPieceCommitmentV1(c)
		require.EqualError(t, err, commcid.ErrIncorrectHash.Error())
		require.Nil(t, decoded)
	})
}

func testMultiHash(code uint64, buf []byte, extra int) multihash.Multihash {
	newBuf := make([]byte, varint.UvarintSize(code)+varint.UvarintSize(uint64(len(buf)))+len(buf)+extra)
	n := varint.PutUvarint(newBuf, code)
	n += varint.PutUvarint(newBuf[n:], uint64(len(buf)))

	copy(newBuf[n:], buf)
	return multihash.Multihash(newBuf)
}
