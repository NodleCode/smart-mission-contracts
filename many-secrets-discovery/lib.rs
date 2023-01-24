#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
pub mod mission {
    use ink_env::{
        hash::{Blake2x256 as Hasher, HashOutput},
        hash_bytes,
    };
    use ink_prelude::vec::Vec;
    use ink_primitives::KeyPtr;
    use ink_storage::traits::{SpreadAllocate, SpreadLayout};
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
        /// The network operator has accepted the mission and deployed it on its fleet
        Deployed,
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
    #[derive(SpreadAllocate)]
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

    impl Mission {
        fn new_init(&mut self) {
            self.owner = self.env().caller();
            self.details = None;
            self.status = Status::Loaded;
        }

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
            ink_lang::utils::initialize_contract(|contract| Self::new_init(contract))
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

            let allowance = Balance::from(max_prizes.clone())
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
        use ink_env::AccountId;
        use ink_lang as ink;

        #[ink::test]
        fn test_merkle_tree() {
            let hasher = |x: &String| -> HashOutputType {
                let mut output = HashOutputType::default();
                hash_bytes::<Hasher>(x.as_bytes(), &mut output);
                output
            };

            // The information that is initially only known to the mission owner/creator
            let mission_owner_secrets = vec![
                "cow".to_string(),
                "yoga".to_string(),
                "wild".to_string(),
                "bill".to_string(),
                "red".to_string(),
                "lurk@6".to_string(),
            ];

            // Mission owner should first hash the secrets and store this vector in a place accessible by the network operator e.g. an IPFS CID
            let leaves = mission_owner_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();

            // Mission owner should then configure the root hash of the mission from tree[0] or use the following function
            let root = CBMT::build_merkle_root(&leaves);

            // Suppose an operator (on behalf of a participants) has discovered the following secrets
            let discovered_secrets = vec!["red".to_string(), "yoga".to_string()];

            let proof_leaves = discovered_secrets
                .iter()
                .map(hasher)
                .collect::<Vec<HashOutputType>>();

            // The operator then hashes the discovered secrets to find their positions in the leaves that the mission owner has shared
            let indices = proof_leaves
                .iter()
                .map(|&hash| leaves.iter().position(|&x| x == hash).unwrap() as u32)
                .collect::<Vec<u32>>();

            // The operator then makes a merkle proof for those leaf indices
            let proof = CBMT::build_merkle_proof(&leaves, &indices).unwrap();

            // The operator then shares the discovered secrets, proof lemmas and proof indices with the contract
            // The contract rebuilds the proof_leaves out of the revealed secrets in the same way as the operator calculated them
            // The contract also rebuilds the proof out of the proof indices and its lemmas
            let rebuilt_proof = MerkleProof::<HashOutputType, HashMerger>::new(
                proof.indices().to_vec(),
                proof.lemmas().to_vec(),
            );

            // Finally the contract uses the rebuilt proof and the knowledge of merkle root to very the proof
            assert!(rebuilt_proof.verify(&root, &proof_leaves))
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
            let hasher = |x: &Vec<u8>| -> HashOutputType {
                let mut output = HashOutputType::default();
                hash_bytes::<Hasher>(x.as_slice(), &mut output);
                output
            };
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
            let max_prizes = mission_owner_secrets.len() as u32;
            assert_eq!(
                mission.kick_off(
                    accounts.eve,
                    deploy_allowance,
                    per_secret_prize,
                    max_prizes as u32,
                    1,
                    root, // 0x8e53fb3f9832a36d03b8282674d91acd583a87cfef77c6f4ec81910f42b5aa70
                    vec![]
                ),
                Ok(())
            );
            assert_eq!(mission.status(), Status::Locked);

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

            set_caller(accounts.eve);
            assert_eq!(mission.accept(), Ok(()));

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

            let operator_earning =
                deploy_allowance + per_secret_prize * Balance::from(discovered_secrets_len);
            assert_eq!(get_balance(accounts.eve), operator_earning);
            assert_eq!(
                get_balance(contract_id()),
                initial_balance - operator_earning
            );
            assert_eq!(mission.status(), Status::Deployed);
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
