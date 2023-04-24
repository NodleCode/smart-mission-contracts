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
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;
    use ink::codegen::StaticEnv;

    use ink::prelude::vec::Vec;
    #[derive(PartialEq, Eq, scale::Encode, scale::Decode, Copy, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(ink::storage::traits::StorageLayout, scale_info::TypeInfo, Debug)
    )]
    pub enum Status {
        /// The initial status of the mission. Whenever a mission is accomplished, the contract goes back to this state
        Loaded,
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
        /// The allowance to the for accomplishing the mission successfully.
        accomplished_allowance: Balance,
        /// The blocknumber from which a locked but unfulfilled mission will be effectively unlocked
        unlock_block_number: BlockNumber,
        /// The hash of the valid finding for the mission
        pub hash: [u8; 32],
        /// Could be the IPFS CID pointing to the mission's bundle
        /// The bundle should contain: manifest, wasm for the edge device, merkle tree of valid findings (all hashed no raw)
        data: Vec<u8>,
    }

    #[ink(storage)]
    pub struct Mission {
        /// The owner is who instantiated the mission
        pub owner: AccountId,
        /// Mission spec
        pub details: Option<Details>,
        /// Mission status
        pub status: Status,
    }

    #[ink(event)]
    pub struct MissionReady {
        #[ink(topic)]
        owner: AccountId,
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
                owner: Mission::env().caller(),
                details: None,
                status: Status::Loaded,
            }
        }
    }
    impl Mission {
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
            Default::default()
        }

        /// Kick a mission by assigning the operator and the allowance for the mission
        #[ink(message, payable)]
        pub fn kick_off(
            &mut self,
            accomplished_allowance: Balance,
            unlock_block_number: BlockNumber,
            hash: [u8; 32],
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

            let allowance = accomplished_allowance;

            if contract_native_balance < allowance {
                return Err(Error::InsufficientBalance);
            }

            Self::env().emit_event(MissionReady {
                owner: self.owner,
                allowance,
                unlock_block_number,
            });

            self.details = Some(Details {
                accomplished_allowance,
                unlock_block_number,
                hash,
                data,
            });
            self.status = Status::Deployed;
            Ok(())
        }

        #[ink(message)]
        /// For the simple mission where only the operator can submit a finding, it's okay for the finding to be in clear.
        /// This is because there couldn't be any front-running or replay attacks.
        pub fn fulfill(&mut self, finding: [u8; 32]) -> Result<()> {
            let _debug = self.env().caller();
            if let Some(mission) = &self.details {
                if self.env().caller() == self.owner {
                    return Err(Error::PermissionDenied);
                }

                let caller_id = to_scalar(&self.env().caller());
                let contract_id = to_scalar(&self.owner());

                let allowance = match self.status_impl() {
                    Status::Loaded => return Err(Error::MissionNotOngoing),
                    Status::Deployed => mission.accomplished_allowance,
                };

                let finding_rp = MontgomeryPoint(finding);
                let mission_hash_rp = MontgomeryPoint(mission.hash);

                if finding_rp * contract_id != mission_hash_rp * caller_id {
                    return Err(Error::IncorrectFinding);
                }

                self.env()
                    .transfer(self.env().caller(), allowance)
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
    fn to_scalar(account: &AccountId) -> Scalar {
        Scalar::from_bytes_mod_order(*AsRef::<[u8; 32]>::as_ref(account))
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
            assert_eq!(mission.kick_off(70, 1, Default::default(), vec![]), Ok(()));

            assert_eq!(
                mission.kick_off(70, 1, Default::default(), vec![]),
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
                mission.kick_off(70, 1, Default::default(), vec![]),
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
                mission.kick_off(70, 1, Default::default(), vec![]),
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
            assert_eq!(mission.kick_off(70, 1, Default::default(), vec![]), Ok(()));

            set_caller(accounts.alice);
            assert_eq!(
                mission.terminate(),
                Err(Error::NotAllowedWhileMissionIsOngoing)
            );
        }

        #[ink::test]
        fn fulfill_after_kickoff_works() {
            use curve25519_dalek::edwards::EdwardsPoint;
            let initial_balance = 100;
            let accounts = default_accounts();

            assert_eq!(get_balance(accounts.frank), 0);

            let message = "Chancellor on brink of second bailout for banks";

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            let contract_owner = mission.owner;

            assert_eq!(contract_owner, accounts.alice);
            set_caller(accounts.alice);
            let allowance = 70;

            let hash = EdwardsPoint::hash_from_bytes::<sha2::Sha512>(message.as_bytes())
                .to_montgomery()
                * to_scalar(&accounts.alice);

            assert_eq!(
                mission.kick_off(allowance, 1, hash.to_bytes(), vec![]),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Deployed);
            {
                let x = mission.owner;
                assert_eq!(x, accounts.alice);
            }
            set_caller(accounts.frank);

            let found_secret = EdwardsPoint::hash_from_bytes::<sha2::Sha512>(message.as_bytes())
                .to_montgomery()
                * to_scalar(&accounts.frank);

            assert_eq!(mission.fulfill(found_secret.to_bytes()), Ok(()));

            assert_eq!(get_balance(accounts.frank), allowance);
            assert_eq!(get_balance(contract_id()), initial_balance - allowance);
            assert_eq!(mission.status(), Status::Loaded);
        }

        #[ink::test]
        fn fulfill_fails_for_owner() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let accomplished_allowance = 70;
            assert_eq!(
                mission.kick_off(accomplished_allowance, 1, Default::default(), vec![]),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Deployed);

            set_caller(accounts.alice);
            assert_eq!(
                mission.fulfill(Default::default()),
                Err(Error::PermissionDenied)
            );
        }

        #[ink::test]
        fn fulfill_fails_if_no_ongoing_mission() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = Mission::new();

            set_caller(accounts.alice);
            let accomplished_allowance = 70;
            assert_eq!(
                mission.kick_off(accomplished_allowance, 2, Default::default(), vec![]),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Deployed);

            advance_block();
            assert_eq!(mission.status(), Status::Deployed);

            advance_block();
            assert_eq!(mission.status(), Status::Loaded);

            set_caller(accounts.eve);
            assert_eq!(
                mission.fulfill(Default::default()),
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
                accomplished_allowance: 70,
                unlock_block_number: 1,
                hash: Default::default(),
                data: "QmQMUCNyCtHKeePsfQvD8gtWs1789HERHUUA6fMhZxZBtA"
                    .as_bytes()
                    .to_vec(),
            };

            set_caller(accounts.alice);
            assert_eq!(
                mission.kick_off(
                    details.accomplished_allowance,
                    details.unlock_block_number,
                    Default::default(),
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
