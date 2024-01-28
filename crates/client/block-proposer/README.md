## Polkadot SDK Update: Reintegration of Encrypted Transactions Feature
This document outlines a recent update to our Polkadot SDK implementation. Previously, we had removed duplicated functionalities from the Polkadot SDK (as detailed in PR [#1268](https://github.com/keep-starknet-strange/madara/pull/1268)). However, to facilitate a new feature involving encrypted transaction handling, we've reintegrated certain aspects of the previously removed code.

### Background
Previous Removal of Duplicated Code
On November 19, 2023, we merged PR [#1268](https://github.com/keep-starknet-strange/madara/pull/1268), which involved removing some crates that were copy-pasted from the Polkadot SDK. This step was taken to streamline our codebase and eliminate redundancies.

### Need for Reintegration
Despite the initial removal, we've identified the need to reintegrate certain components to support encrypted transaction handling.

### New Feature: Encrypted Transaction Handling in apply_extrinsics
We have reintroduced specific parts of the previously removed code to implement encrypted transaction handling in the `apply_extrinsics` function. This change allows us to:

Detect if an encrypted transaction pool is being used.
Process encrypted transactions by decrypting them before inclusion in a block.
Implementation Details
Reintroduction of Code
The reintroduction involved carefully selecting and merging relevant parts of the previously removed Polkadot SDK code.