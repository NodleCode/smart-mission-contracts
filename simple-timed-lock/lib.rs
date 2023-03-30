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
    use ink::prelude::vec::Vec;
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
        /// The allowance for the mission
        allowance: Balance,
        /// The blocknumber from which a locked but unfulfilled mission will be effectively unlocked
        unlock_block_number: BlockNumber,
        /// Could be the IPFS CID pointing to the mission's bundle (manifest + wasm for the edge device)
        data: Vec<u8>,
    }

    impl Details {
        fn status(&self, block_number: BlockNumber) -> Status {
            if block_number < self.unlock_block_number {
                Status::Locked
            } else {
                Status::Loaded
            }
        }
    }

    #[ink(storage)]
    pub struct Mission {
        /// The owner is who instantiated the mission
        owner: AccountId,
        /// Mission spec
        mission: Option<Details>,
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
    pub struct MissionAccomplished {
        memo: Vec<u8>,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        NotAllowedWhileMissionIsOngoing,
        InsufficientBalance,
        PermissionDenied,
        UnlockBlockNumberIsInPast,
        MissionNotOngoing,
        AllowanceTransferFailed,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Default for Mission {
        fn default() -> Self {
            Self {
                owner: AccountId::from([0u8; 32]),
                mission: None,
            }
        }
    }
    impl Mission {
        #[inline]
        fn status_impl(&self) -> Status {
            if let Some(mission) = &self.mission {
                mission.status(self.env().block_number())
            } else {
                Status::Loaded
            }
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
            allowance: Balance,
            unlock_block_number: BlockNumber,
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
            if contract_native_balance < allowance {
                return Err(Error::InsufficientBalance);
            }

            self.mission = Some(Details {
                operator,
                allowance,
                unlock_block_number,
                data,
            });

            Self::env().emit_event(MissionReady {
                owner: self.owner,
                operator,
                allowance,
                unlock_block_number,
            });
            Ok(())
        }

        #[ink(message)]
        pub fn fulfill(&mut self, memo: Vec<u8>) -> Result<()> {
            if let Some(mission) = &self.mission {
                if self.env().caller() != mission.operator {
                    return Err(Error::PermissionDenied);
                }
                if mission.status(self.env().block_number()) != Status::Locked {
                    return Err(Error::MissionNotOngoing);
                }

                self.env()
                    .transfer(mission.operator, mission.allowance)
                    .map_err(|_| Error::AllowanceTransferFailed)?;

                self.mission = None;
                Self::env().emit_event(MissionAccomplished { memo });
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
            self.mission.clone()
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
            assert_eq!(mission.kick_off(accounts.eve, 80, 1, vec![]), Ok(()));

            assert_eq!(
                mission.kick_off(accounts.eve, 10, 1, vec![]),
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
                mission.kick_off(accounts.eve, 80, 1, vec![]),
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
                mission.kick_off(accounts.eve, 80, 1, vec![]),
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
            assert_eq!(mission.kick_off(accounts.eve, 80, 1, vec![]), Ok(()));

            set_caller(accounts.alice);
            assert_eq!(
                mission.terminate(),
                Err(Error::NotAllowedWhileMissionIsOngoing)
            );
        }

        #[ink::test]
        fn fulfill_works() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let allowance = 80;
            assert_eq!(mission.kick_off(accounts.eve, allowance, 1, vec![]), Ok(()));
            assert_eq!(mission.status(), Status::Locked);

            set_caller(accounts.eve);
            assert_eq!(
                mission.fulfill("off-chain proof ref: x".as_bytes().to_vec()),
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
            let allowance = 80;
            assert_eq!(mission.kick_off(accounts.eve, allowance, 1, vec![]), Ok(()));
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
            let allowance = 80;
            assert_eq!(mission.kick_off(accounts.eve, allowance, 2, vec![]), Ok(()));
            assert_eq!(mission.status(), Status::Locked);

            advance_block();
            assert_eq!(mission.status(), Status::Locked);

            advance_block();
            assert_eq!(mission.status(), Status::Loaded);

            set_caller(accounts.eve);
            assert_eq!(
                mission.fulfill("memo".as_bytes().to_vec()),
                Err(Error::MissionNotOngoing)
            );
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
                allowance: 80,
                unlock_block_number: 1,
                data: "QmQMUCNyCtHKeePsfQvD8gtWs1789HERHUUA6fMhZxZBtA"
                    .as_bytes()
                    .to_vec(),
            };

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(
                    details.operator,
                    details.allowance,
                    details.unlock_block_number,
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
