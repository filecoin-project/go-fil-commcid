# go-fil-commcid
[![](https://img.shields.io/badge/made%20by-Protocol%20Labs-blue.svg?style=flat-square)](http://ipn.io)
[![CircleCI](https://circleci.com/gh/filecoin-project/go-fil-commcid.svg?style=svg)](https://circleci.com/gh/filecoin-project/go-fil-commcid)
[![codecov](https://codecov.io/gh/filecoin-project/go-fil-commcid/branch/master/graph/badge.svg)](https://codecov.io/gh/filecoin-project/go-fil-commcid)

Conversion Utilities Between CID and Piece/Data/Replica Commitments

## Description

This provides utility functions to convert from
commitment hashes used by Filecoin and Content IDs that meet [the CIDv1 standard](https://github.com/multiformats/cid)

## Table of Contents
* [Background](https://github.com/filecoin-project/go-fil-commcid/tree/master#background)
* [Usage](https://github.com/filecoin-project/go-fil-commcid/tree/master#usage)
* [Contribute](https://github.com/filecoin-project/go-fil-commcid/tree/master#contribute)

## Background

See the [Filecoin PoRep Spec](https://filecoin-project.github.io/specs/#algorithms__porep) and the [Filecoin Paper](https://filecoin.io/filecoin.pdf) for how these commitment hashes (Piece Commitment, Data Commitment, Replica Commitment) are generated.

This library adds codes neccesary to convert those hashes to CIDs

Currently, the serialization format for all Commitment CIDs is raw, cause each
hash is either a hash of raw data, or a hash of a concentenation of raw hashes. We do not attempt to convert these to IPLD data at this time.

We define 2 hash types, one for sealed data and one for unsealed data, with 8 more hash identifiers reserved for future peice, sector, and replica construction methods

## Usage

**Requires go 1.13**

Install the module in your package or app with `go get "github.com/filecoin-project/go-fil-commcid"`

### Generating CIDs for CommP, CommD, CommR

```golang
package mypackage

import (
        commcid "github.com/filecoin-project/go-fil-commcid"
)

var commP []byte
var commD []byte
var commR []byte            

pieceCID := commcid.PieceCommmitmentV1ToCID(commP)
unsealedSectorCID := commcid.DataCommmitmentV1ToCID(commD)
sealedSectorCID := commcid.ReplicaCommmitmentV1ToCID(commR)

```

### Getting a raw CommP, CommR, CommD from a CID

```golang
package mypackage

import (
        commcid "github.com/filecoin-project/go-fil-commcid"
)

var pieceCID cid.Cid
var unsealedSectorCID cid.Cid
var sealedSectorCID cid.Cid           

// will error if pieceCID does not have the correct codec & hash type
commP, err := commcid.CIDToPieceCommitmentV1(pieceCID)

// will error if unsealedSectorCID does not have the correct codec & hash type
commD, err := commcid.CIDToDataCommitmentV1(unsealedSectorCID)

// will error if sealedSectorCID does not have the correct codec & hash type
commR, err := commcid.CIDToReplicaCommitmentV1(sealedSectorCID)
```

### Going from arbitrary commitment to CID and back

As Filecoin evolves, there will likely be new and better constructions for both sealed and unsealed data. Note `V1` in front of the above method names.

To support future evolution, we provide more generalized methods for
going back and forth:


```golang
package mypackage

import (
        commcid "github.com/filecoin-project/go-fil-commcid"
)

var commIn []byte
var hashingAlgorithm FilecoinMultihashType          

commCID := commcid.CommmitmentToCID(commIn, hashingAlgorithm)

commOut, hashOut, err := commcid.CIDToCommitment(commCID)

```

## Contributing
PRs are welcome!  Please first read the design docs and look over the current code.  PRs against 
master require approval of at least two maintainers.  For the rest, please see our 
[CONTRIBUTING](https://github.com/filecoin-project/go-fil-commcid/CONTRIBUTING.md) guide.

## License
This repository is dual-licensed under Apache 2.0 and MIT terms.

Copyright 2019. Protocol Labs, Inc.
