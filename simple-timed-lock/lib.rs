#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
pub mod mission {
    use ink_prelude::vec::Vec;
    use ink_primitives::KeyPtr;
    use ink_storage::traits::{SpreadAllocate, SpreadLayout};

    #[derive(PartialEq, Eq, scale::Encode, scale::Decode, SpreadLayout, Copy, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout, Debug)
    )]
    pub enum Status {
        /// The initial status of the mission. Whenever a mission is accomplished, the contract goes back to this state
        Loaded,
        /// The mission owner has locked the allowance for the mission and kicked off the mission
        Locked,
    }

    impl SpreadAllocate for Status {
        fn allocate_spread(_ptr: &mut KeyPtr) -> Self {
            Status::Loaded
        }
    }

    #[derive(SpreadAllocate, SpreadLayout, scale::Encode, scale::Decode, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(
            scale_info::TypeInfo,
            ink_storage::traits::StorageLayout,
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
    #[derive(SpreadAllocate)]
    pub struct Mission {
        /// The owner is who instantiated the mission
        owner: AccountId,
        /// Mission spec
        mission: Option<Details>,
    }
    #[ink(event)]
    pub struct MissionAccomplished {
        memo: Vec<u8>,
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

    impl Mission {
        fn new_init(&mut self) {
            self.owner = self.env().caller();
            self.mission = None;
        }

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
            ink_lang::utils::initialize_contract(|contract| Self::new_init(contract))
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
        use ink_env::AccountId;
        use ink_lang as ink;

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
            ink_env::test::callee::<ink_env::DefaultEnvironment>()
        }

        fn set_caller(sender: AccountId) {
            ink_env::test::set_caller::<ink_env::DefaultEnvironment>(sender);
        }

        fn default_accounts() -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
            ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
        }

        fn get_balance(account_id: AccountId) -> Balance {
            ink_env::test::get_account_balance::<ink_env::DefaultEnvironment>(account_id)
                .expect("Account Not Found")
        }

        fn set_balance(account_id: AccountId, balance: Balance) {
            ink_env::test::set_account_balance::<ink_env::DefaultEnvironment>(account_id, balance)
        }

        fn advance_block() {
            ink_env::test::advance_block::<ink_env::DefaultEnvironment>();
        }
    }
}
