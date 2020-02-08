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

	c := commcid.DataCommitmentV1ToCID(randBytes)

	require.Equal(t, c.Prefix().Codec, uint64(cid.Raw))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(commcid.FC_UNSEALED_V1))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToDataCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(uint64(commcid.FC_UNSEALED_V1), randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.Raw, hash)
			decoded, err := commcid.CIDToDataCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, bytes.Equal(decoded, randBytes))
		})

		t.Run("error on incorrect CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, err := commcid.CIDToDataCommitmentV1(c)
			require.EqualError(t, err, commcid.ErrIncorrectCodec.Error())
			require.Nil(t, decoded)
		})
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(uint64(commcid.FC_UNSEALED_V1), randBytes, 5)
		c := cid.NewCidV1(cid.Raw, hash)
		decoded, err := commcid.CIDToDataCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
		decoded, err := commcid.CIDToDataCommitmentV1(c)
		require.EqualError(t, err, commcid.ErrIncorrectHash.Error())
		require.Nil(t, decoded)
	})
}

func TestReplicaCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c := commcid.ReplicaCommitmentV1ToCID(randBytes)

	require.Equal(t, c.Prefix().Codec, uint64(cid.Raw))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(uint64(commcid.FC_SEALED_V1)))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToReplicaCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(uint64(commcid.FC_SEALED_V1), randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.Raw, hash)
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
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(uint64(commcid.FC_SEALED_V1), randBytes, 5)
		c := cid.NewCidV1(cid.Raw, hash)
		decoded, err := commcid.CIDToReplicaCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
		decoded, err := commcid.CIDToReplicaCommitmentV1(c)
		require.EqualError(t, err, commcid.ErrIncorrectHash.Error())
		require.Nil(t, decoded)
	})
}

func TestPieceCommitmentToCID(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	c := commcid.PieceCommitmentV1ToCID(randBytes)

	require.Equal(t, c.Prefix().Codec, uint64(cid.Raw))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(commcid.FC_UNSEALED_V1))
	require.Equal(t, decoded.Length, len(randBytes))
	require.True(t, bytes.Equal(decoded.Digest, randBytes))
}

func TestCIDToPieceCommitment(t *testing.T) {
	randBytes := make([]byte, 32)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(uint64(commcid.FC_UNSEALED_V1), randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.Raw, hash)
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
		hash := testMultiHash(uint64(commcid.FC_UNSEALED_V1), randBytes, 5)
		c := cid.NewCidV1(cid.Raw, hash)
		decoded, err := commcid.CIDToPieceCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
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
