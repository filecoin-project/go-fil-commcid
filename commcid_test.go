package commcid_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
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

func TestPieceCommitmentToPieceMhCID(t *testing.T) {
	randBytes := make([]byte, 33)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)
	randHeight := randBytes[0]
	randBytes = randBytes[1:]

	c, err := commcid.DataCommitmentV1ToPieceMhCID(randBytes, randHeight)
	require.NoError(t, err)

	require.Equal(t, c.Prefix().Codec, uint64(cid.Raw))
	mh := c.Hash()
	decoded, err := multihash.Decode([]byte(mh))
	require.NoError(t, err)
	require.Equal(t, decoded.Code, uint64(commcid.FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE))
	require.Equal(t, decoded.Length, len(randBytes)+1)
	require.True(t, decoded.Digest[0] == randHeight)
	require.True(t, bytes.Equal(decoded.Digest[1:], randBytes))

	_, err = commcid.DataCommitmentV1ToPieceMhCID(randBytes[1:], randHeight)
	require.Regexp(t, "^commitments must be 32 bytes long", err.Error())
}

func TestPieceMhCIDToPieceCommitment(t *testing.T) {
	randBytes := make([]byte, 33)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)
	// Height must be at least 7
	randBytes[0] = (randBytes[0] % (255 - 7)) + 7

	t.Run("with correct hash format", func(t *testing.T) {
		hash := testMultiHash(commcid.FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE, randBytes, 0)

		t.Run("decodes raw commitment hash when correct cid format", func(t *testing.T) {
			c := cid.NewCidV1(cid.Raw, hash)
			decoded, height, err := commcid.PieceMhCIDToDataCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, height == randBytes[0])
			require.True(t, bytes.Equal(decoded, randBytes[1:]))
		})

		t.Run("don't error on non-Raw CID format", func(t *testing.T) {
			c := cid.NewCidV1(cid.DagCBOR, hash)
			decoded, height, err := commcid.PieceMhCIDToDataCommitmentV1(c)
			require.NoError(t, err)
			require.True(t, height == randBytes[0])
			require.True(t, bytes.Equal(decoded, randBytes[1:]))
		})
	})

	t.Run("error on incorrectly formatted hash", func(t *testing.T) {
		hash := testMultiHash(commcid.FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE, randBytes, 5)
		c := cid.NewCidV1(cid.Raw, hash)
		decoded, _, err := commcid.PieceMhCIDToDataCommitmentV1(c)
		require.Error(t, err)
		require.Regexp(t, "^Error decoding data commitment hash:", err.Error())
		require.Nil(t, decoded)
	})
	t.Run("error on wrong hash type", func(t *testing.T) {
		encoded, err := multihash.Encode(randBytes, multihash.SHA2_256)
		require.NoError(t, err)
		c := cid.NewCidV1(cid.Raw, multihash.Multihash(encoded))
		decoded, _, err := commcid.PieceMhCIDToDataCommitmentV1(c)
		require.EqualError(t, err, commcid.ErrIncorrectHash.Error())
		require.Nil(t, decoded)
	})
}

func TestTreeHeight(t *testing.T) {
	// Add test fixtures
	noFr32PaddingTests := map[string]struct {
		size   uint64
		height uint8
	}{
		"127OfEach0-1-2-3":          {127 * 4, 4},
		"512-bytes-should-pad-over": {512, 5},
		"0":                         {0, 0},
		"1":                         {1, 0},
		"31":                        {31, 0},
		"32":                        {32, 1},
		"127":                       {127, 2},
		"32GiB":                     {32 << 30, 31},
		"64GiB":                     {64 << 30, 32},
	}

	for name, tc := range noFr32PaddingTests {
		t.Run(fmt.Sprintf("non-fr32-padding %s", name), func(t *testing.T) {
			require.Equal(t, tc.height, commcid.UnpaddedSizeToV1TreeHeight(tc.size))
		})
	}

	// Add test fixtures
	fr32PaddingTests := map[string]struct {
		size   uint64
		height uint8
	}{
		"127OfEach0-1-2-3":              {127 * 4, 4},
		"512-bytes-should-not-pad-over": {512, 4},
		"0":                             {0, 0},
		"1":                             {1, 0},
		"31":                            {31, 0},
		"32":                            {32, 0},
		"127":                           {127, 2},
		"128":                           {128, 2},
		"129":                           {129, 3},
		"32GiB":                         {32 << 30, 30},
		"64GiB":                         {64 << 30, 31},
	}

	for name, tc := range fr32PaddingTests {
		t.Run(fmt.Sprintf("with-fr32-padding %s", name), func(t *testing.T) {
			require.Equal(t, tc.height, commcid.Fr32PaddedSizeToV1TreeHeight(tc.size))
		})
	}
}

func TestPieceMhCIDandV1CIDPieceCommitmentConverters(t *testing.T) {
	randBytes := make([]byte, 33)
	_, err := rand.Read(randBytes)
	require.NoError(t, err)
	// Height must be at least 7
	randBytes[0] = (randBytes[0] % (255 - 7)) + 7

	mhv1 := testMultiHash(multihash.SHA2_256_TRUNC254_PADDED, randBytes[1:], 0)
	cidv1 := cid.NewCidV1(cid.FilCommitmentUnsealed, mhv1)

	mhv2 := testMultiHash(commcid.FR32_SHA256_TRUNC254_PADDED_BINARY_TREE_CODE, randBytes, 0)
	cidv2 := cid.NewCidV1(cid.Raw, mhv2)

	t.Run("convert v1 piece cid + height to piece mh cid", func(t *testing.T) {
		c, err := commcid.ConvertDataCommitmentV1V1CIDtoPieceMhCID(cidv1, randBytes[0])
		require.NoError(t, err)
		require.True(t, c.Equals(cidv2))
	})

	t.Run("convert piece mh cid to v1 piece cid + height", func(t *testing.T) {
		c, height, err := commcid.ConvertDataCommitmentV1PieceMhCIDToV1CID(cidv2)
		require.NoError(t, err)
		require.True(t, c.Equals(cidv1))
		require.Equal(t, randBytes[0], height)
	})

	// Add test fixtures
	tests := map[string]struct {
		v1CidStr string
		height   uint8
		v2CidStr string
	}{
		"127OfEach0-1-2-3": {"baga6ea4seaqes3nobte6ezpp4wqan2age2s5yxcatzotcvobhgcmv5wi2xh5mbi", commcid.UnpaddedSizeToV1TreeHeight(127 * 4), "bafkzcibbarew3lqmzhrgl37fuadoqbrguxofyqe6luyvlqjzqtfpnsgvz7lak"},
		"empty32GiB":       {"baga6ea4seaqao7s73y24kcutaosvacpdjgfe5pw76ooefnyqw4ynr3d2y6x2mpq", commcid.Fr32PaddedSizeToV1TreeHeight(32 << 30), "bafkzcibbdydx4x66gxcqveyduviaty2jrjhl5x7ttrbloefxgdmoy6whv6td4"},
		"empty64GiB":       {"baga6ea4seaqomqafu276g53zko4k23xzh4h4uecjwicbmvhsuqi7o4bhthhm4aq", commcid.Fr32PaddedSizeToV1TreeHeight(64 << 30), "bafkzcibbd7teabngx7rxo6ktxcww56j7b7fbasnsaqlfj4vech3xaj4zz3hae"},
	}

	for name, tc := range tests {
		t.Run(fmt.Sprintf("%s-v1-to-v2", name), func(t *testing.T) {
			v1Cid, err := cid.Parse(tc.v1CidStr)
			require.NoError(t, err)

			v2Cid, err := cid.Parse(tc.v2CidStr)
			require.NoError(t, err)

			computedV2Cid, err := commcid.ConvertDataCommitmentV1V1CIDtoPieceMhCID(v1Cid, tc.height)
			require.NoError(t, err)

			require.True(t, v2Cid.Equals(computedV2Cid))
		})

		t.Run(fmt.Sprintf("%s-v2-to-v1", name), func(t *testing.T) {
			v1Cid, err := cid.Parse(tc.v1CidStr)
			require.NoError(t, err)

			v2Cid, err := cid.Parse(tc.v2CidStr)
			require.NoError(t, err)

			computedV1Cid, computedHeight, err := commcid.ConvertDataCommitmentV1PieceMhCIDToV1CID(v2Cid)
			require.NoError(t, err)

			require.True(t, v1Cid.Equals(computedV1Cid))
			require.Equal(t, tc.height, computedHeight)
		})
	}
}

func testMultiHash(code uint64, buf []byte, extra int) multihash.Multihash {
	newBuf := make([]byte, varint.UvarintSize(code)+varint.UvarintSize(uint64(len(buf)))+len(buf)+extra)
	n := varint.PutUvarint(newBuf, code)
	n += varint.PutUvarint(newBuf[n:], uint64(len(buf)))

	copy(newBuf[n:], buf)
	return multihash.Multihash(newBuf)
}
