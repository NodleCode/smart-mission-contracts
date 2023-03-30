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

    #[derive(PartialEq, Eq, scale::Encode, scale::Decode, Copy, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(ink::storage::traits::StorageLayout, scale_info::TypeInfo, Debug)
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
        /// The allowance to the for accomplishing the mission successfully.
        /// This is an addition on top of the `deploy_allowance`.
        accomplished_allowance: Balance,
        /// The blocknumber from which a locked but unfulfilled mission will be effectively unlocked
        unlock_block_number: BlockNumber,
        /// The hash of the valid finding for the mission
        hash: Hash,
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

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NotAllowedWhileMissionIsOngoing,
        InsufficientBalance,
        PermissionDenied,
        UnlockBlockNumberIsInPast,
        MissionNotOngoing,
        MissionAlreadyDeployed,
        AllowanceTransferFailed,
        IncorrectFinding,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for Mission {
        fn default() -> Self {
            Self {
                owner: AccountId::from([0u8; 32]),
                details: None,
                status: Status::Loaded,
            }
        }
    }
    impl Mission {
        fn new_init(&mut self) {
            self.owner = self.env().caller();
            self.details = None;
            self.status = Status::Loaded;
        }

        #[inline]
        fn status_impl(&self) -> Status {
            if let Some(mission) = &self.details {
                if self.env().block_number() < mission.unlock_block_number {
                    return self.status;
                }
            }
            Status::Loaded
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
            accomplished_allowance: Balance,
            unlock_block_number: BlockNumber,
            hash: Hash,
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

            let allowance = deploy_allowance + accomplished_allowance;

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
                accomplished_allowance,
                unlock_block_number,
                hash,
                data,
            });
            self.status = Status::Locked;
            Ok(())
        }

        #[ink(message)]
        /// If the operator chooses to collect the base deploy_allowance before attempting to fulfill
        /// the mission, they will need to accept the mission formally by calling this API. However
        /// calling `accept` is not needed, if they are willing to fulfil the mission in a single
        /// call and collect both deploy_allowance and accomplished_allowance at once. This second
        /// approach is possible only when they have been able to discover the correct `finding`
        /// which is needed for the `fulfill` API.
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
        /// For the simple mission where only the operator can submit a finding, it's okay for the finding to be in clear.
        /// This is because there couldn't be any front-running or replay attacks.
        pub fn fulfill(&mut self, finding: Vec<u8>) -> Result<()> {
            if let Some(mission) = &self.details {
                if self.env().caller() != mission.operator {
                    return Err(Error::PermissionDenied);
                }

                let allowance = match self.status_impl() {
                    Status::Loaded => return Err(Error::MissionNotOngoing),
                    Status::Locked => mission.accomplished_allowance + mission.deploy_allowance,
                    Status::Deployed => mission.accomplished_allowance,
                };

                let mut output = <Hasher as HashOutput>::Type::default();
                hash_bytes::<Hasher>(&finding, &mut output);
                let hash = Hash::from(output);

                if hash != mission.hash {
                    return Err(Error::IncorrectFinding);
                }

                self.env()
                    .transfer(mission.operator, allowance)
                    .map_err(|_| Error::AllowanceTransferFailed)?;

                Self::env().emit_event(MissionAccomplished {});

                self.details = None;
                self.status = Status::Loaded;
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
            self.details.clone()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[ink::test]
        fn kick_mission_fails_if_mission_is_ongoing() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(accounts.eve, 10, 70, 1, Hash::default(), vec![]),
                Ok(())
            );

            assert_eq!(
                mission.kick_off(accounts.eve, 10, 70, 1, Hash::default(), vec![]),
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
                mission.kick_off(accounts.eve, 10, 70, 1, Hash::default(), vec![]),
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
                mission.kick_off(accounts.eve, 10, 70, 1, Hash::default(), vec![]),
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
                mission.kick_off(accounts.eve, 10, 70, 1, Hash::default(), vec![]),
                Ok(())
            );

            set_caller(accounts.alice);
            assert_eq!(
                mission.terminate(),
                Err(Error::NotAllowedWhileMissionIsOngoing)
            );
        }

        #[ink::test]
        fn fulfill_after_kickoff_works() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let accomplished_allowance = 70;
            let allowance = deploy_allowance + accomplished_allowance;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    accomplished_allowance,
                    1,
                    [
                        0xce, 0xc3, 0x42, 0x01, 0x77, 0x04, 0x91, 0x0e, 0xae, 0x75, 0xa5, 0x6a,
                        0x65, 0xdd, 0x3c, 0x83, 0x84, 0x4c, 0x85, 0xec, 0x0c, 0xe7, 0x3c, 0x4d,
                        0xbb, 0x3a, 0xcb, 0xbf, 0xac, 0xb6, 0x91, 0x6a
                    ]
                    .into(), // 0xcec342017704910eae75a56a65dd3c83844c85ec0ce73c4dbb3acbbfacb6916a
                    vec![]
                ),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Locked);

            set_caller(accounts.eve);
            assert_eq!(
                mission.fulfill(
                    "It always seems impossible until it's done. - Nelson Mandela"
                        .as_bytes()
                        .to_vec()
                ),
                Ok(())
            );

            assert_eq!(get_balance(accounts.eve), allowance);
            assert_eq!(get_balance(contract_id()), initial_balance - allowance);
            assert_eq!(mission.status(), Status::Loaded);
        }

        #[ink::test]
        fn fulfill_after_accept_works() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let accomplished_allowance = 70;
            let allowance = accomplished_allowance + deploy_allowance;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    accomplished_allowance,
                    1,
                    [
                        0xce, 0xc3, 0x42, 0x01, 0x77, 0x04, 0x91, 0x0e, 0xae, 0x75, 0xa5, 0x6a,
                        0x65, 0xdd, 0x3c, 0x83, 0x84, 0x4c, 0x85, 0xec, 0x0c, 0xe7, 0x3c, 0x4d,
                        0xbb, 0x3a, 0xcb, 0xbf, 0xac, 0xb6, 0x91, 0x6a
                    ]
                    .into(),
                    vec![]
                ),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Locked);

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));
            assert_eq!(get_balance(accounts.eve), deploy_allowance);
            assert_eq!(
                get_balance(contract_id()),
                initial_balance - deploy_allowance
            );
            assert_eq!(mission.status(), Status::Deployed);

            set_caller(accounts.eve);
            assert_eq!(
                mission.fulfill(
                    "It always seems impossible until it's done. - Nelson Mandela"
                        .as_bytes()
                        .to_vec()
                ),
                Ok(())
            );
            assert_eq!(get_balance(accounts.eve), allowance);
            assert_eq!(get_balance(contract_id()), initial_balance - allowance);
            assert_eq!(mission.status(), Status::Loaded);
        }

        #[ink::test]
        fn fulfill_fails_for_non_operator() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let accomplished_allowance = 70;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    accomplished_allowance,
                    1,
                    Hash::default(),
                    vec![]
                ),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Locked);

            set_caller(accounts.django);
            assert_eq!(mission.fulfill(vec![]), Err(Error::PermissionDenied));
        }

        #[ink::test]
        fn fulfill_fails_if_no_ongoing_mission() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let deploy_allowance = 10;
            let accomplished_allowance = 70;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    accomplished_allowance,
                    2,
                    Hash::default(),
                    vec![]
                ),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Locked);

            advance_block();
            assert_eq!(mission.status(), Status::Locked);

            advance_block();
            assert_eq!(mission.status(), Status::Loaded);

            set_caller(accounts.eve);
            assert_eq!(mission.fulfill(vec![]), Err(Error::MissionNotOngoing));
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
                accomplished_allowance: 70,
                unlock_block_number: 1,
                hash: Hash::default(),
                data: "QmQMUCNyCtHKeePsfQvD8gtWs1789HERHUUA6fMhZxZBtA"
                    .as_bytes()
                    .to_vec(),
            };

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(
                    details.operator,
                    details.deploy_allowance,
                    details.accomplished_allowance,
                    details.unlock_block_number,
                    Hash::default(),
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
