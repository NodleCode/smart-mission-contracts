# smart-mission-contracts

[![Build and Test Smart Contracts](https://github.com/NodleCode/smart-mission-contracts/actions/workflows/ci.yml/badge.svg)](https://github.com/NodleCode/smart-mission-contracts/actions/workflows/ci.yml)

A library of smart contract samples for Smart Missions.

## Prerequisites
Install dependencies 

    cargo install cargo-dylint dylint-link
    cargo install --force --locked cargo-contract

## Build 
Change directory to the resepctive mission (e.g. cd simple-mission) and then

    cargo test
    cargo contract test
    cargo contract build
    

## Bug Bounty Terms

Contracts in this repository are examples of how to design and implement Smart Missions atop the Nodle Chain, but are not deployed as long-lived assets on either Eden or Paradis networks.

As such, bounties reported against this repository (rather than against the Chain which operates and stores Contract deployments) are out of scope. 

## License

Copyright 2023 Intergalactic Labs, Inc. Released under the GNU General Public License, version 3.0. See `LICENSE` for further details.
