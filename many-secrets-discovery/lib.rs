/*
 * This file is part of Nodle Smart Missions distributed at https://github.com/NodleCode/smart-mission-contracts
 * Copyright (C) 2020-2023 Nodle International
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#![cfg_attr(not(feature = "std"), no_std)]

#[ink::contract]
pub mod mission {
    use ink::env::{
        hash::{Blake2x256 as Hasher, HashOutput},
        hash_bytes,
    };
    use ink::prelude::vec::Vec;
    use merkle_cbt::{merkle_tree::Merge, MerkleProof, CBMT as ExCBMT};

    pub struct HashMerger;
    impl Merge for HashMerger {
        type Item = <Hasher as HashOutput>::Type;
        fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
            let mut output = Self::Item::default();
            let mut input = left.to_vec();
            input.extend_from_slice(right);
            hash_bytes::<Hasher>(&input, &mut output);
            output
        }
    }
    pub type HashOutputType = <Hasher as HashOutput>::Type;
    pub type CBMT = ExCBMT<HashOutputType, HashMerger>;

    #[derive(PartialEq, Eq, scale::Encode, scale::Decode, Copy, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout, Debug)
    )]
    pub enum Status {
        /// The initial status of the mission. Whenever a mission is accomplished, the contract goes back to this state
        Loaded,
        /// The mission owner has locked the allowance for the mission and kicked off the mission
        Locked,
        /// The network operator has accepted the mission and deployed it on its fleet
        Deployed,
    }

    #[derive(scale::Encode, scale::Decode, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(
            scale_info::TypeInfo,
            ink::storage::traits::StorageLayout,
            Debug,
            Eq,
            PartialEq
        )
    )]
    pub struct Details {
        /// The whitelisted operator for the mission
        operator: AccountId,
        /// The allowance to the operator for deploying the mission regardless of the result
        deploy_allowance: Balance,
        /// The amount this mission pays per each discovery of a secret.
        per_secret_prize: Balance,
        /// The maximum number of prizes to claim.
        max_prizes: u32,
        /// The blocknumber from which a locked but unfulfilled mission will be effectively unlocked
        unlock_block_number: BlockNumber,
        /// The root hash of a static complete binary merkle tree where each leave is a hash of a secret
        root: HashOutputType,
        /// Could be the IPFS CID pointing to the mission's bundle
        /// The bundle should contain: manifest, wasm for the edge device, merkle tree of valid findings (all hashed no raw)
        data: Vec<u8>,
    }

    #[ink(storage)]
    pub struct Mission {
        /// The owner is who instantiated the mission
        owner: AccountId,
        /// Mission spec
        details: Option<Details>,
        /// Mission status
        status: Status,
        /// The merkle tree indices of the successfully claimed secrets
        claimed_indices: Vec<u32>,
    }

    #[ink(event)]
    pub struct MissionReady {
        #[ink(topic)]
        owner: AccountId,
        #[ink(topic)]
        operator: AccountId,
        allowance: Balance,
        unlock_block_number: BlockNumber,
    }

    #[ink(event)]
    /// Mission finished successfully
    pub struct MissionAccomplished {}

    #[ink(event)]
    /// Mission is deployed on the target fleet as claimed by the network operator
    pub struct MissionDeployed {}

    #[ink(event)]
    /// Mission has paid out some prize for a successful discovery
    pub struct MissionPaidOut {
        prize: Balance,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NotAllowedWhileMissionIsOngoing,
        InsufficientBalance,
        Incalculable,
        PermissionDenied,
        UnlockBlockNumberIsInPast,
        MissionNotOngoing,
        MissionNotDeployed,
        MissionAlreadyDeployed,
        AllowanceTransferFailed,
        IncorrectDiscovery,
        SecretClaimedBefore,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for Mission {
        fn default() -> Self {
            Self {
                owner: AccountId::from([0u8; 32]),
                details: None,
                status: Status::Loaded,
                claimed_indices: Default::default(),
            }
        }
    }
    impl Mission {
        #[inline]
        fn status_impl(&self) -> Status {
            if let Some(details) = &self.details {
                if self.env().block_number() < details.unlock_block_number {
                    return self.status;
                }
            }
            Status::Loaded
        }

        #[inline]
        fn prize_left_impl(&self) -> u32 {
            self.details
                .as_ref()
                .and_then(|details| {
                    details
                        .max_prizes
                        .checked_sub(self.claimed_indices.len() as u32)
                })
                .unwrap_or_default()
        }

        /// Creates a new instance of this contract.
        #[ink(constructor, payable)]
        pub fn new() -> Self {
            let mut mission: Mission = Default::default();
            mission.owner = mission.env().caller();
            mission
        }

        /// Kick a mission by assigning the operator and the allowance for the mission
        #[ink(message, payable)]
        pub fn kick_off(
            &mut self,
            operator: AccountId,
            deploy_allowance: Balance,
            per_secret_prize: Balance,
            max_prizes: u32,
            unlock_block_number: BlockNumber,
            root: HashOutputType,
            data: Vec<u8>,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::PermissionDenied);
            }
            if self.status_impl() != Status::Loaded {
                return Err(Error::NotAllowedWhileMissionIsOngoing);
            }
            if self.env().block_number() >= unlock_block_number {
                return Err(Error::UnlockBlockNumberIsInPast);
            }

            let contract_native_balance = self
                .env()
                .balance()
                .saturating_add(self.env().transferred_value());

            let allowance = Balance::from(max_prizes)
                .checked_mul(per_secret_prize)
                .and_then(|l| l.checked_add(deploy_allowance))
                .ok_or(Error::Incalculable)?;

            if contract_native_balance < allowance {
                return Err(Error::InsufficientBalance);
            }

            Self::env().emit_event(MissionReady {
                owner: self.owner,
                operator,
                allowance,
                unlock_block_number,
            });

            self.details = Some(Details {
                operator,
                deploy_allowance,
                per_secret_prize,
                max_prizes,
                unlock_block_number,
                root,
                data,
            });
            self.status = Status::Locked;
            self.claimed_indices.clear();
            Ok(())
        }

        #[ink(message)]
        /// The operator needs to accept the mission formally and then allowed to claim discovering
        /// mission's secrets. Accepting the mission also allows the `deploy_allowance` to be
        /// transferred to the operator. Only the mission's designated operator can accept it.
        pub fn accept(&mut self) -> Result<()> {
            if let Some(mission) = &self.details {
                if self.env().caller() != mission.operator {
                    return Err(Error::PermissionDenied);
                }

                match self.status_impl() {
                    Status::Loaded => return Err(Error::MissionNotOngoing),
                    Status::Locked => (),
                    Status::Deployed => return Err(Error::MissionAlreadyDeployed),
                }

                self.env()
                    .transfer(mission.operator, mission.deploy_allowance)
                    .map_err(|_| Error::AllowanceTransferFailed)?;

                Self::env().emit_event(MissionDeployed {});

                self.status = Status::Deployed;
                Ok(())
            } else {
                Err(Error::MissionNotOngoing)
            }
        }

        #[ink(message)]
        /// For the simple mission where only the operator can claim they have discovered some secrets,
        /// So it would be okay for the secrets to be in clear text because they become obsolete         
        /// immediately. The claim should then have the proof lemmas and indices for the merkle tree.
        pub fn claim(
            &mut self,
            discovered_secrets: Vec<Vec<u8>>,
            proof_indices: Vec<u32>,
            proof_lemmas: Vec<HashOutputType>,
        ) -> Result<()> {
            if let Some(details) = &self.details {
                if self.env().caller() != details.operator {
                    return Err(Error::PermissionDenied);
                }

                if self.status_impl() != Status::Deployed {
                    return Err(Error::MissionNotDeployed);
                }

                if proof_indices
                    .iter()
                    .any(|x| self.claimed_indices.contains(x))
                {
                    return Err(Error::SecretClaimedBefore);
                }

                let proof_leaves = discovered_secrets
                    .iter()
                    .map(|x| {
                        let mut output = HashOutputType::default();
                        hash_bytes::<Hasher>(x, &mut output);
                        output
                    })
                    .collect::<Vec<HashOutputType>>();

                let proof = MerkleProof::<HashOutputType, HashMerger>::new(
                    proof_indices.clone(),
                    proof_lemmas,
                );

                if !proof.verify(&details.root, &proof_leaves) {
                    return Err(Error::IncorrectDiscovery);
                }

                let prize_left = self.prize_left_impl();
                let claim_len = proof_leaves.len() as u32;
                let entitlement = prize_left.min(claim_len);

                let prize = Balance::from(entitlement)
                    .checked_mul(details.per_secret_prize)
                    .ok_or(Error::Incalculable)?;

                self.env()
                    .transfer(details.operator, prize)
                    .map_err(|_| Error::AllowanceTransferFailed)?;

                Self::env().emit_event(MissionPaidOut { prize });

                if entitlement == prize_left {
                    Self::env().emit_event(MissionAccomplished {});
                    self.details = None;
                    self.status = Status::Loaded;
                    self.claimed_indices.clear();
                } else {
                    self.claimed_indices.extend_from_slice(&proof_indices);
                }

                Ok(())
            } else {
                Err(Error::MissionNotOngoing)
            }
        }

        #[ink(message)]
        /// Terminate the contract and transfer its value to the owner
        pub fn terminate(&mut self) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::PermissionDenied);
            }
            if self.status_impl() != Status::Loaded {
                return Err(Error::NotAllowedWhileMissionIsOngoing);
            }

            self.env().terminate_contract(self.owner)
        }

        #[ink(message)]
        pub fn status(&self) -> Status {
            self.status_impl()
        }

        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        #[ink(message)]
        pub fn details(&self) -> Option<Details> {
            if self.status_impl() != Status::Loaded {
                self.details.clone()
            } else {
                None
            }
        }

        #[ink(message)]
        pub fn claimed_indices(&self) -> Vec<u32> {
            if self.status_impl() != Status::Loaded {
                self.claimed_indices.clone()
            } else {
                Vec::new()
            }
        }

        #[ink(message)]
        /// The number of prizes yet to be claimed
        pub fn prize_left(&self) -> u32 {
            if self.status_impl() != Status::Loaded {
                self.prize_left_impl()
            } else {
                0
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn hasher(x: &Vec<u8>) -> HashOutputType {
            let mut output = HashOutputType::default();
            hash_bytes::<Hasher>(x.as_slice(), &mut output);
            output
        }

        #[ink::test]
        fn kick_mission_fails_if_mission_is_ongoing() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(accounts.eve, 10, 7, 9, 1, HashOutputType::default(), vec![]),
                Ok(())
            );

            assert_eq!(
                mission.kick_off(accounts.eve, 10, 7, 9, 1, HashOutputType::default(), vec![]),
                Err(Error::NotAllowedWhileMissionIsOngoing)
            );
        }

        #[ink::test]
        fn kick_mission_fails_for_non_owner() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.eve);
            assert_eq!(
                mission.kick_off(accounts.eve, 10, 7, 9, 1, HashOutputType::default(), vec![]),
                Err(Error::PermissionDenied)
            );
        }

        #[ink::test]
        fn kick_mission_fails_if_unlock_block_number_is_in_past() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            advance_block();

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(accounts.eve, 10, 7, 9, 1, HashOutputType::default(), vec![]),
                Err(Error::UnlockBlockNumberIsInPast)
            );
        }

        #[ink::test]
        #[should_panic]
        fn terminate_works() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let _ = mission.terminate();
        }

        #[ink::test]
        fn terminate_fails_for_non_owner() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.eve);
            assert_eq!(mission.terminate(), Err(Error::PermissionDenied));
        }

        #[ink::test]
        fn terminate_fails_if_mission_is_ongoing() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(accounts.eve, 10, 7, 9, 1, HashOutputType::default(), vec![]),
                Ok(())
            );

            set_caller(accounts.alice);
            assert_eq!(
                mission.terminate(),
                Err(Error::NotAllowedWhileMissionIsOngoing)
            );
        }

        #[ink::test]
        fn claim_secrets_works() {
            // The information that is initially only known to the mission owner/creator
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
                "bill".as_bytes().to_vec(),
                "red".as_bytes().to_vec(),
                "lurk@6".as_bytes().to_vec(),
            ];
            // Mission owner should first hash the secrets and store this vector in a place accessible by the network operator e.g. an IPFS CID
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            // Mission owner should then configure the root hash of the mission from tree[0] or use the following function
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 4;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes,
                    1,
                    root, // 0x8e53fb3f9832a36d03b8282674d91acd583a87cfef77c6f4ec81910f42b5aa70
                    vec![]
                ),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Locked);
            assert_eq!(mission.prize_left(), max_prizes);

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));
            assert_eq!(mission.status(), Status::Deployed);

            // Suppose an operator (on behalf of a participants) has discovered the following secrets
            let discovered_secrets = vec!["red".as_bytes().to_vec(), "yoga".as_bytes().to_vec()];
            let discovered_secrets_len = discovered_secrets.len() as u32;
            // The operator then hashes the discovered secrets to find their positions in the leaves that the mission owner has shared
            let proof_leaves = discovered_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices = proof_leaves
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            // The operator then makes a merkle proof for those leaf indices
            let proof = CBMT::build_merkle_proof(&leaves, &indices).unwrap();

            // First claim
            assert_eq!(
                mission.claim(
                    discovered_secrets,
                    proof.indices().to_vec(), // [9, 6]
                    proof.lemmas().to_vec()   // [
                                              // 0xe7afca49ceb08f875382d75f0aecb780d64ecce5610ded8d91bdb8b5734b9101,
                                              // 0x49dacac652e57fba5307c78dc071cf54b2d5914e2bbf59f33e728431356fe36f,
                                              // 0x056ec8ed2c97f247470d7c1211d665437f3bca14a9e1c28306750bc444532a3b
                                              // ]
                ),
                Ok(())
            );
            assert_eq!(mission.prize_left(), max_prizes - discovered_secrets_len);
            let operator_earning =
                deploy_allowance + per_secret_prize * Balance::from(discovered_secrets_len);
            assert_eq!(get_balance(accounts.eve), operator_earning);
            assert_eq!(
                get_balance(contract_id()),
                initial_balance - operator_earning
            );

            // Check the mission is still ongoing
            assert_eq!(mission.status(), Status::Deployed);

            // Get prepared for a second claim
            let discovered_secrets_2 = vec![
                "cow".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
                "bill".as_bytes().to_vec(),
                "lurk@6".as_bytes().to_vec(),
            ];
            let discovered_secrets_len_2 = discovered_secrets_2.len() as u32;
            // We want to test the case the discovered secrets exceeds the prizes left
            assert!(mission.prize_left() < discovered_secrets_len_2);
            let proof_leaves_2 = discovered_secrets_2
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices_2 = proof_leaves_2
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            let proof_2 = CBMT::build_merkle_proof(&leaves, &indices_2).unwrap();

            // Second claim
            assert_eq!(
                mission.claim(
                    discovered_secrets_2,
                    proof_2.indices().to_vec(),
                    proof_2.lemmas().to_vec()
                ),
                Ok(())
            );
            // Check no prizes left to claim
            assert_eq!(mission.prize_left(), 0);
            // Check mission is now accomplished and back to the loaded status
            assert_eq!(mission.status(), Status::Loaded);
            // Check claimed indices are cleared
            assert!(mission.claimed_indices.is_empty());
            // Because the number of prizes to be claimed was less than the number of discovered secretes in the second claim,
            // check the operator has increased earning only for the prizes that was left to claim.
            let operator_earning_2 = operator_earning
                + per_secret_prize * Balance::from(max_prizes - discovered_secrets_len);
            assert_eq!(get_balance(accounts.eve), operator_earning_2);
        }

        #[ink::test]
        fn claim_overlap_with_a_previous_successful_claim_fails() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

            let discovered_secrets = vec!["wild".as_bytes().to_vec(), "cow".as_bytes().to_vec()];
            let proof_leaves = discovered_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices = proof_leaves
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            let proof = CBMT::build_merkle_proof(&leaves, &indices).unwrap();
            assert_eq!(
                mission.claim(
                    discovered_secrets,
                    proof.indices().to_vec(),
                    proof.lemmas().to_vec()
                ),
                Ok(())
            );

            // Check the mission is still ongoing
            assert_eq!(mission.status(), Status::Deployed);

            let discovered_secrets_2 = vec!["cow".as_bytes().to_vec(), "yoga".as_bytes().to_vec()];
            let proof_leaves_2 = discovered_secrets_2
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices_2 = proof_leaves_2
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            let proof_2 = CBMT::build_merkle_proof(&leaves, &indices_2).unwrap();

            // Second overlapping claim: "cow" is claimed before
            assert_eq!(
                mission.claim(
                    discovered_secrets_2,
                    proof_2.indices().to_vec(),
                    proof_2.lemmas().to_vec()
                ),
                Err(Error::SecretClaimedBefore)
            );
            // Check mission is remains ongoing
            assert_eq!(mission.status(), Status::Deployed);
            assert_eq!(mission.claimed_indices.len(), 2);
        }

        #[ink::test]
        fn claim_from_non_operator_fails() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

            let discovered_secrets = vec!["wild".as_bytes().to_vec(), "cow".as_bytes().to_vec()];
            let proof_leaves = discovered_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices = proof_leaves
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            let proof = CBMT::build_merkle_proof(&leaves, &indices).unwrap();

            set_caller(accounts.django);
            assert_eq!(
                mission.claim(
                    discovered_secrets.clone(),
                    proof.indices().to_vec(),
                    proof.lemmas().to_vec()
                ),
                Err(Error::PermissionDenied)
            );
            set_caller(accounts.eve);
            assert_eq!(
                mission.claim(
                    discovered_secrets,
                    proof.indices().to_vec(),
                    proof.lemmas().to_vec()
                ),
                Ok(())
            );
        }

        #[ink::test]
        fn claim_wrong_secret_fails() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

            // Suppose an adversary uses the known hashes for the following secrets
            let target_secrets = vec!["wild".as_bytes().to_vec(), "cow".as_bytes().to_vec()];
            // But no knowing all the corresponding secrets correctly
            let claim_secrets = vec!["orange".as_bytes().to_vec(), "cow".as_bytes().to_vec()];
            let proof_leaves = target_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices = proof_leaves
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            let proof = CBMT::build_merkle_proof(&leaves, &indices).unwrap();
            assert_eq!(
                mission.claim(
                    claim_secrets,
                    proof.indices().to_vec(),
                    proof.lemmas().to_vec()
                ),
                Err(Error::IncorrectDiscovery)
            );
        }

        #[ink::test]
        fn empty_claim_fails() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

            let discovered_secrets = vec![];
            let proof_indices = vec![];
            let proof_lemmas = vec![];
            assert_eq!(
                mission.claim(discovered_secrets, proof_indices, proof_lemmas),
                Err(Error::IncorrectDiscovery)
            );
        }

        #[ink::test]
        fn claim_fails_if_mission_not_accepted() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            let discovered_secrets = vec!["wild".as_bytes().to_vec(), "cow".as_bytes().to_vec()];
            let proof_leaves = discovered_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let indices = proof_leaves
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();
            let proof = CBMT::build_merkle_proof(&leaves, &indices).unwrap();
            set_caller(accounts.eve);
            assert_eq!(
                mission.claim(
                    discovered_secrets.clone(),
                    proof.indices().to_vec(),
                    proof.lemmas().to_vec()
                ),
                Err(Error::MissionNotDeployed)
            );

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

            set_caller(accounts.eve);
            assert_eq!(
                mission.claim(
                    discovered_secrets,
                    proof.indices().to_vec(),
                    proof.lemmas().to_vec()
                ),
                Ok(())
            );
        }

        #[ink::test]
        fn accept_fails_if_mission_not_kicked_off() {
            let accounts = default_accounts();

            set_caller(accounts.alice);
            let mut mission = Mission::new();

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Err(Error::MissionNotOngoing));
        }

        #[ink::test]
        fn accept_fails_for_callees_other_than_operator() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            set_caller(accounts.django);
            assert_eq!(mission.accept(), Err(Error::PermissionDenied));

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));
        }

        #[ink::test]
        fn accept_fails_if_mission_is_already_accepted() {
            let mission_owner_secrets = vec![
                "cow".as_bytes().to_vec(),
                "yoga".as_bytes().to_vec(),
                "wild".as_bytes().to_vec(),
            ];
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();
            let root = CBMT::build_merkle_root(&leaves);

            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let per_secret_prize = 7;
            let max_prizes = 3;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root,
                    vec![]
                ),
                Ok(())
            );

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Err(Error::MissionAlreadyDeployed));
        }

        #[ink::test]
        fn prizes_left() {
            let mut mission = Mission::new();
            assert_eq!(mission.prize_left(), 0);

            let accounts = default_accounts();
            let details = Details {
                operator: accounts.eve,
                deploy_allowance: 10,
                per_secret_prize: 7,
                max_prizes: 9,
                unlock_block_number: 1,
                root: HashOutputType::default(),
                data: vec![],
            };
            mission.details = Some(details);
            mission.status = Status::Loaded;

            assert_eq!(mission.prize_left(), 0);

            mission.status = Status::Locked;
            assert_eq!(mission.prize_left(), 9);

            mission.status = Status::Deployed;
            assert_eq!(mission.prize_left(), 9);

            mission.claimed_indices.extend_from_slice(&[5, 2, 1]);
            assert_eq!(mission.prize_left(), 6);

            mission
                .claimed_indices
                .extend_from_slice(&[7, 8, 3, 6, 4, 0]);
            assert_eq!(mission.prize_left(), 0);

            mission.claimed_indices.extend_from_slice(&[9, 10, 11]);
            assert_eq!(mission.prize_left(), 0);
        }

        #[ink::test]
        fn mission_reads_correctly() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();
            let details = Details {
                operator: accounts.eve,
                deploy_allowance: 10,
                per_secret_prize: 7,
                max_prizes: 9,
                unlock_block_number: 1,
                root: HashOutputType::default(),
                data: "QmQMUCNyCtHKeePsfQvD8gtWs1789HERHUUA6fMhZxZBtA"
                    .as_bytes()
                    .to_vec(),
            };

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(
                    details.operator,
                    details.deploy_allowance,
                    details.per_secret_prize,
                    details.max_prizes,
                    details.unlock_block_number,
                    HashOutputType::default(),
                    details.data.clone()
                ),
                Ok(())
            );
            assert_eq!(mission.details(), Some(details));
            assert_eq!(mission.owner(), accounts.alice);
        }

        fn contract_id() -> AccountId {
            ink::env::test::callee::<ink::env::DefaultEnvironment>()
        }

        fn set_caller(sender: AccountId) {
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(sender);
        }

        fn default_accounts() -> ink::env::test::DefaultAccounts<ink::env::DefaultEnvironment> {
            ink::env::test::default_accounts::<ink::env::DefaultEnvironment>()
        }

        fn get_balance(account_id: AccountId) -> Balance {
            ink::env::test::get_account_balance::<ink::env::DefaultEnvironment>(account_id)
                .expect("Account Not Found")
        }

        fn set_balance(account_id: AccountId, balance: Balance) {
            ink::env::test::set_account_balance::<ink::env::DefaultEnvironment>(account_id, balance)
        }

        fn advance_block() {
            ink::env::test::advance_block::<ink::env::DefaultEnvironment>();
        }
    }
}
