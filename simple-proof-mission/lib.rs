#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
pub mod simple_proof_mission {
    use ink_env::{
        hash::{Blake2x256 as Hasher, HashOutput},
        hash_bytes,
    };
    use ink_prelude::vec::Vec;
    use ink_primitives::KeyPtr;
    use ink_storage::traits::{SpreadAllocate, SpreadLayout};

    #[derive(PartialEq, Eq, scale::Encode, scale::Decode, SpreadLayout, Copy, Clone)]
    #[cfg_attr(
        feature = "std",
        derive(scale_info::TypeInfo, ink_storage::traits::StorageLayout, Debug)
    )]
    pub enum MissionStatus {
        /// The initial status of the mission. Whenever a mission is accomplished, the contract goes back to this state
        Loaded,
        /// The mission owner has locked the allowance for the mission and kicked off the mission
        Locked,
        /// The network operator has accepted the mission and deployed it on its fleet
        Deployed,
    }

    impl SpreadAllocate for MissionStatus {
        fn allocate_spread(_ptr: &mut KeyPtr) -> Self {
            MissionStatus::Loaded
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
    pub struct SimpleProofMission {
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
    #[derive(SpreadAllocate)]
    pub struct OwnedMission {
        /// The owner is who instantiated the mission
        owner: AccountId,
        /// Mission spec
        mission: Option<SimpleProofMission>,
        /// Mission status
        status: MissionStatus,
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

    impl OwnedMission {
        fn new_init(&mut self) {
            self.owner = self.env().caller();
            self.mission = None;
            self.status = MissionStatus::Loaded;
        }

        #[inline]
        fn status_impl(&self) -> MissionStatus {
            if let Some(mission) = &self.mission {
                if self.env().block_number() < mission.unlock_block_number {
                    return self.status;
                }
            }
            MissionStatus::Loaded
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
            deploy_allowance: Balance,
            accomplished_allowance: Balance,
            unlock_block_number: BlockNumber,
            hash: Hash,
            data: Vec<u8>,
        ) -> Result<()> {
            if self.env().caller() != self.owner {
                return Err(Error::PermissionDenied);
            }
            if self.status_impl() != MissionStatus::Loaded {
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

            self.mission = Some(SimpleProofMission {
                operator,
                deploy_allowance,
                accomplished_allowance,
                unlock_block_number,
                hash,
                data,
            });
            self.status = MissionStatus::Locked;
            Ok(())
        }

        #[ink(message)]
        pub fn accept(&mut self) -> Result<()> {
            if let Some(mission) = &self.mission {
                if self.env().caller() != mission.operator {
                    return Err(Error::PermissionDenied);
                }

                match self.status_impl() {
                    MissionStatus::Loaded => return Err(Error::MissionNotOngoing),
                    MissionStatus::Locked => (),
                    MissionStatus::Deployed => return Err(Error::MissionAlreadyDeployed),
                }

                self.env()
                    .transfer(mission.operator, mission.deploy_allowance)
                    .map_err(|_| Error::AllowanceTransferFailed)?;

                Self::env().emit_event(MissionDeployed {});

                self.status = MissionStatus::Deployed;
                Ok(())
            } else {
                Err(Error::MissionNotOngoing)
            }
        }

        #[ink(message)]
        /// For the simple mission where only the operator can submit a finding, it's okay for the finding to be in clear.
        /// This is because there couldn't be any front-running or replay attacks.
        pub fn fulfill(&mut self, finding: Vec<u8>) -> Result<()> {
            if let Some(mission) = &self.mission {
                if self.env().caller() != mission.operator {
                    return Err(Error::PermissionDenied);
                }

                let allowance = match self.status_impl() {
                    MissionStatus::Loaded => return Err(Error::MissionNotOngoing),
                    MissionStatus::Locked => {
                        mission.accomplished_allowance + mission.deploy_allowance
                    }
                    MissionStatus::Deployed => mission.accomplished_allowance,
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

                self.mission = None;
                self.status = MissionStatus::Loaded;
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
            if self.status_impl() != MissionStatus::Loaded {
                return Err(Error::NotAllowedWhileMissionIsOngoing);
            }

            self.env().terminate_contract(self.owner)
        }

        #[ink(message)]
        pub fn status(&self) -> MissionStatus {
            self.status_impl()
        }

        #[ink(message)]
        pub fn owner(&self) -> AccountId {
            self.owner
        }

        #[ink(message)]
        pub fn mission(&self) -> Option<SimpleProofMission> {
            self.mission.clone()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ink_env::{AccountId, Hash};
        use ink_lang as ink;

        #[ink::test]
        fn kick_mission_fails_if_mission_is_ongoing() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();

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
            let mut mission = OwnedMission::new();

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
            let mut mission = OwnedMission::new();

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
            let mut mission = OwnedMission::new();

            set_caller(accounts.alice);
            let _ = mission.terminate();
        }

        #[ink::test]
        fn terminate_fails_for_non_owner() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();

            set_caller(accounts.eve);
            assert_eq!(mission.terminate(), Err(Error::PermissionDenied));
        }

        #[ink::test]
        fn terminate_fails_if_mission_is_ongoing() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();

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
            let mut mission = OwnedMission::new();

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
            assert_eq!(mission.status(), MissionStatus::Locked);

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
            assert_eq!(mission.status(), MissionStatus::Loaded);
        }

        #[ink::test]
        fn fulfill_after_accept_works() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();

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
            assert_eq!(mission.status(), MissionStatus::Locked);

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));
            assert_eq!(get_balance(accounts.eve), deploy_allowance);
            assert_eq!(
                get_balance(contract_id()),
                initial_balance - deploy_allowance
            );
            assert_eq!(mission.status(), MissionStatus::Deployed);

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
            assert_eq!(mission.status(), MissionStatus::Loaded);
        }

        #[ink::test]
        fn fulfill_fails_for_non_operator() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();

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
            assert_eq!(mission.status(), MissionStatus::Locked);

            set_caller(accounts.django);
            assert_eq!(mission.fulfill(vec![]), Err(Error::PermissionDenied));
        }

        #[ink::test]
        fn fulfill_fails_if_no_ongoing_mission() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();

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
            assert_eq!(mission.status(), MissionStatus::Locked);

            advance_block();
            assert_eq!(mission.status(), MissionStatus::Locked);

            advance_block();
            assert_eq!(mission.status(), MissionStatus::Loaded);

            set_caller(accounts.eve);
            assert_eq!(mission.fulfill(vec![]), Err(Error::MissionNotOngoing));
        }

        #[ink::test]
        fn mission_reads_correctly() {
            let initial_balance = 100;
            let accounts = default_accounts();

            set_caller(accounts.alice);
            set_balance(contract_id(), initial_balance);
            let mut mission = OwnedMission::new();
            let mission_details = SimpleProofMission {
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
                    mission_details.operator,
                    mission_details.deploy_allowance,
                    mission_details.accomplished_allowance,
                    mission_details.unlock_block_number,
                    Hash::default(),
                    mission_details.data.clone()
                ),
                Ok(())
            );
            assert_eq!(mission.mission(), Some(mission_details));
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
