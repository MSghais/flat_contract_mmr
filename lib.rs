#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
use pink_extension as pink;

#[pink::contract(env=PinkEnvironment)]
mod merkle_contain_range {
    type E = Vec<u8>;
    use super::pink;
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };
    use scale::{Decode, Encode};

    use ink_storage::{
        traits::{
             SpreadAllocate, 
        // PackedLayout,
        // SpreadLayout, 
        // push_spread_root,
        // pull_spread_root, 
        }, Mapping};
    use pink::{
        chain_extension::SigType, derive_sr25519_key, get_public_key, http_get, sign, verify,
        PinkEnvironment, 
    };

    use arber:: {
        MerkleMountainRange,
        Store,
        VecStore,
        // hash_with_index, 
        // Error,
        // Result,
        // Hashable,
        // MerkleProof,
    };


    #[ink(storage)]
    #[derive(SpreadAllocate)]
    pub struct MerkleFlatContract {
        admin: AccountId,
        attestation_pubkey: Vec<u8>,
        attestation_privkey: Vec<u8>,
        poap_code: Vec<String>,
      /// Map from the account to the redemption index
        ///
        /// Thus the POAP code should be `poap_code[index]`.
        redeem_by_account: Mapping<AccountId, u32>,
        /// The number of total redeemed code.
        total_redeemed: u32,
        /// Map from verified accounts to usernames
        username_by_account: Mapping<AccountId, String>,
        /// Map from verified usernames to accounts
        account_by_username: Mapping<String, AccountId>,
        account_vec: Mapping<AccountId, E>,

        // data: Vec<u8>,
        // datas: Vec<Profil>,
        // datas: Vec<Profil>,
        // user_mapping:Mapping<String,Profil>,

        hash_values: Vec<String>,
  
    }

    

    #[derive(Encode, Decode, Debug, PartialEq, Eq, Copy, Clone)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum ErrorContract {
        InvalidUrl,
        RequestFailed,
        NoClaimFound,
        InvalidAddressLength,
        InvalidAddress,
        NoPermission,
        InvalidSignature,
        UsernameAlreadyInUse,
        AccountAlreadyInUse,
        CantInitMerkleMountainRange,
    }

    impl MerkleFlatContract {
        #[ink(constructor)]
        pub fn default() -> Self {
            // Generate a Sr25519 key pair
            let privkey = derive_sr25519_key!(b"gist-attestation-key");
            let pubkey = get_public_key!(&privkey, SigType::Sr25519);
            // Save sender as the contract admin
            let admin = Self::env().caller();

            // Create a hash data by default for the MMR 
            let s = VecStore::<E>::new();
            let merkle = MerkleMountainRange::new(0, s);

            // This call is required in order to correctly initialize the
            // `Mapping`s of our contract.
            ink_lang::codegen::initialize_contract(|contract: &mut Self| {
                contract.admin = admin;
                contract.attestation_privkey = privkey;
                contract.attestation_pubkey = pubkey;
                contract.total_redeemed = 0u32;
            })
       
        }

  

        #[ink(constructor)]
        pub fn new_mmr() -> Self {
            // Generate a Sr25519 key pair
            let privkey = derive_sr25519_key!(b"gist-attestation-key");
            let pubkey = get_public_key!(&privkey, SigType::Sr25519);
            // Save sender as the contract admin
            let admin = Self::env().caller();

            // Create a hash data by default for the MMR 
            let mut hashes:Vec<String> = Vec::new();
            let s = VecStore::<E>::new();
            let merkle = MerkleMountainRange::new(0, s);
            
            // This call is required in order to correctly initialize the
            // `Mapping`s of our contract.
            ink_lang::codegen::initialize_contract(|contract: &mut Self| {
                contract.admin = admin;
                contract.attestation_privkey = privkey;
                contract.attestation_pubkey = pubkey;
                contract.total_redeemed = 0u32;
                contract.poap_code = Vec::new();
                // contract.mmr.insert("1".to_string(), &merkle_on_chain);
                // contract.store_integrity.insert(&merkle_root.clone(), &merkle_on_chain.clone());
               
            })
       
        }

        /// Attests a Github Gist by the raw file url. (Query only)
        ///
        /// It sends a HTTPS request to the url and extract an address from the claim ("This gist
        /// is owned by address: 0x..."). Once the claim is verified, it returns a signed
        /// attestation with the pair `(github_username, account_id)`.
        #[ink(message)]
        pub fn append_data(&self, url: String) -> Result<SignedAttestation, ErrorContract> {
            // Verify the URL
            let gist_url = parse_gist_url(&url)?;
            // Fetch the gist content
            let resposne = http_get!(url);
            if resposne.status_code != 200 {
                return Err(ErrorContract::RequestFailed);
            }
            let body = resposne.body;
            // Verify the claim and extract the account id
            let account_id = extract_claim(&body)?;
            let attestation = Attestation {
                username: gist_url.username,
                account_id,
            };
            let result = self.sign_attestation(attestation);
            Ok(result)
        }

        /// Signs the `attestation` with the attestation key pair.
        pub fn sign_attestation(&self, attestation: Attestation) -> SignedAttestation {
            let encoded = Encode::encode(&attestation);
            let signature = sign!(&encoded, &self.attestation_privkey, SigType::Sr25519);
            SignedAttestation {
                attestation,
                signature,
            }
        }

        /// Verifies the signed attestation and return the inner data.
        pub fn verify_attestation(&self, signed: SignedAttestation) -> Result<Attestation, ErrorContract> {
            let encoded = Encode::encode(&signed.attestation);
            if !verify!(
                &encoded,
                &self.attestation_pubkey,
                &signed.signature,
                SigType::Sr25519
            ) {
                return Err(ErrorContract::InvalidSignature);
            }
            Ok(signed.attestation)
        }


    }

    #[derive(PartialEq, Eq, Debug)]
    struct GistUrl {
        username: String,
        gist_id: String,
        filename: String,
    }

    /// Parses a Github Gist url.
    ///
    /// - Returns a parsed [GistUrl] struct if the input is a valid url;
    /// - Otherwise returns an [Error].
    fn parse_gist_url(url: &str) -> Result<GistUrl, ErrorContract> {
        let path = url
            .strip_prefix("https://gist.githubusercontent.com/")
            .ok_or(ErrorContract::InvalidUrl)?;
        let components: Vec<_> = path.split('/').collect();
        if components.len() < 5 {
            return Err(ErrorContract::InvalidUrl);
        }
        Ok(GistUrl {
            username: components[0].to_string(),
            gist_id: components[1].to_string(),
            filename: components[4].to_string(),
        })
    }

    const CLAIM_PREFIX: &str = "This gist is owned by address: 0x";
    const ADDRESS_LEN: usize = 64;

    /// Extracts the ownerhip of the gist from a claim in the gist body.
    ///
    /// A valid claim must have the statement "This gist is owned by address: 0x..." in `body`. The
    /// address must be the 256 bits public key of the Substrate account in hex.
    ///
    /// - Returns a 256-bit `AccountId` representing the owner account if the claim is valid;
    /// - otherwise returns an [Error].
    fn extract_claim(body: &[u8]) -> Result<AccountId, ErrorContract> {
        let body = String::from_utf8_lossy(body);
        let pos = body.find(CLAIM_PREFIX).ok_or(ErrorContract::NoClaimFound)?;
        let addr: String = body
            .chars()
            .skip(pos)
            .skip(CLAIM_PREFIX.len())
            .take(ADDRESS_LEN)
            .collect();
        let addr = addr.as_bytes();
        let account_id = decode_accountid_256(addr)?;
        Ok(account_id)
    }

    /// Decodes a hex string as an 256-bit AccountId32
    fn decode_accountid_256(addr: &[u8]) -> Result<AccountId, ErrorContract> {
        use hex::FromHex;
        if addr.len() != ADDRESS_LEN {
            return Err(ErrorContract::InvalidAddressLength);
        }
        let bytes = <[u8; 32]>::from_hex(addr).or(Err(ErrorContract::InvalidAddress))?;
        Ok(AccountId::from(bytes))
    }


    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct Attestation {
        username: String,
        account_id: AccountId,
    }

    #[derive(Encode, Decode, Debug)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub struct SignedAttestation {
        attestation: Attestation,
        signature: Vec<u8>,
    }

    /// Unit tests in Rust are normally defined within such a `#[cfg(test)]`
    /// module and test functions are marked with a `#[test]` attribute.
    /// The below code is technically just normal Rust code.
    #[cfg(test)]
    mod tests {
        /// Imports all the definitions from the outer scope so we can use them here.
        use super::*;

        /// Imports `ink_lang` so we can use `#[ink::test]`.
        use ink_lang as ink;
        use arber:: {
            MerkleMountainRange,
            Hashable,
            Store,
            VecStore,
            Error as ErrorMerkle,
            hash_with_index, 
            MerkleProof,
        };

        fn make_mmr(num_leafs: u8) -> MerkleMountainRange<E, VecStore<E>> {
            let s = VecStore::<E>::new();
            let mut mmr = MerkleMountainRange::<E, VecStore<E>>::new(0, s);
        
            (0..=num_leafs.saturating_sub(1)).for_each(|i| {
                let n = vec![i, 10];
                let _ = mmr.append(&n).unwrap();
            });
        
            mmr
        }
        
        #[test]
        fn make_mmr_default() {

            let s = VecStore::<E>::new();
            let mut mmr = MerkleMountainRange::<E, VecStore<E>>::new(0, s);
            (0..=10_u8.saturating_sub(1)).for_each(|i| {
                let n = vec![i, 10];
                let _ = mmr.append(&n).unwrap();
            });
        }
        
        #[test]
        fn new_works() -> Result<(), ErrorMerkle> {
            let mmr = make_mmr(6);
            let hash = mmr.hash(5)?;
            assert_eq!(hash, mmr.hash(5)?);
            Ok(())
        }

        #[allow(clippy::vec_init_then_push)]
        pub fn hash_values() -> Vec<String> {
            let mut hashvalues = Vec::new();
            // list of hex values of Hasher hashes
            hashvalues.push("1ced8f5be2db23a6513eba4d819c73806424748a7bc6fa0d792cc1c7d1775a9778e894aa91413f6eb79ad5ae2f871eafcc78797e4c82af6d1cbfb1a294a10d10".to_string()); // 1
            hashvalues.push("c5faca15ac2f93578b39ef4b6bbb871bdedce4ddd584fd31f0bb66fade3947e6bb1353e562414ed50638a8829ff3daccac7ef4a50acee72a5384ba9aeb604fc9".to_string()); // 2
            hashvalues.push("4d3d9d4c8da746e2dcf236f31b53850e0e35a07c1d6082be51b33e7c1e11c39cf5e309953bf56866b0ccede95cdf3ae5f9823f6cf3bcc6ada19cf21b09884717".to_string()); // (1-2)
            hashvalues.push("6f760b9e9eac89f07ab0223b0f4acb04d1e355d893a1b86a83f4d4b405adee99913dacb7bc3d6e6a46f996e59b965e82b1ffa1994062bcd8bef867bcf743c07c".to_string()); // 3
            hashvalues.push("e8e70dc170e14333627b32c20ac6051fb9b6bd369c036afbaca2d9cd7ac3de65aeda9d9651423af4343fd8e13f6481081b473e22a58f3f0e2a28143e4fb70bc2".to_string()); // 4
            hashvalues.push("ebf20fe26f69ab804b760fbf55eac3eba8f6cffa3f85d7b0c29ffd4a66a28deecc6f9eaaae758c49334f8b10ccfc743cee732e5486166cd3313a1881f7e0519e".to_string()); // (3-4)
            hashvalues.push("8989c1ea10efac5b9897e9c227b307fd029005ba4f8e1590ec23942c3e788d7d280bb3cdbbd76cc9814755ee508174cb1d79a45f575a33240ac4b892ada7f850".to_string()); // (1-2)(3-4)
            hashvalues.push("73776e3e4cd3684316d26ec93cc6c438497ace5b08e359698667af6dbded88b6750ba0b2c11ba7d52b69180f1924884a158d0b83d87ca9c65d2dae9d73387e43".to_string()); // 5
            hashvalues.push("8d322d4b02d9fcfb05bc70e486406e53c3cf9b97a252bf64752cafc5c2aaf95baef7f6e30d0a64826921ad01ec9d8c010805367078e5b5963ab4be3efd8f4a78".to_string()); // 6
            hashvalues.push("4a10141b2ba124991ddd81b4df78655f582872ba67928bbfc48282609de20ca40f745f622989cf3b71c790de6136173f6282780b2b7770b561f239ecddd40b78".to_string()); // (5-6)
                                                                                                                                                                            // index 10 ^
            hashvalues.push("d5c47f63555ae063383c2a0df82bf309d90932bc8dd66a056d80e4d913e821faacf7e0e962c7bbac6c193e1e638b58b8baa1e71f57a945958b84c11536b7a82d".to_string()); // 7
            hashvalues.push("818af2ae014b14c85a35639901ac6bfc47908bcbd94a7f5211627b1f52f316a994e1296503701dd6827a8e5969d33d1d0b68c452eb95e481035b168a6c0f09c4".to_string()); // 8
            hashvalues.push("5b2abeb00cacb7465131a995bd4f5463032e69e1d3d9a55823536660d130a41bb23b529eec173ddd88a42e5db97cf6983cad0b36ef3de452ac66aba9f37b08ee".to_string()); // (7-8)
            hashvalues.push("53d5d4b1b2f78468fea0292af1cb9e63a2e7460a66cc741756166e135817f20a6b96b60a76dee7f83615d881dfd58e3830003177d4aff13e392889e36f8c5718".to_string()); // (5-6)(7-8)
            hashvalues.push("84247c7a397b4e7314a2a5edc993b12196fcbd2d8b3793d7cf8a63e9c5c8004103874260defe34a4ac739ed21d58bb9c325f96ba9d917d63295f71f45ce0054c".to_string()); // (1-2)(3-4)(5-6)(7-8)
            hashvalues.push("2b57bf7664a4de943d93e4f5473a42da0d7a35065afd559303196fcc33414e73a91042f8d238fcaca45a93b17e577ad15191f95c6d7cf7c19e240a1e05100ad6".to_string()); // 9
            hashvalues.push("f2e74cbc3eff574bbc45333c30edb947858543afda4cafdde2903324c9de0bd908b00575c556bd7b8aa2e32a32598a4d5f95cd4490b60a567a3d53680a3310f2".to_string()); // 10
            hashvalues.push("7c7f5fb40b9d000435c001b05ab6e1409160d24292d8acb9bbd0936a07613fa82ccb01d65b92d5cd3f2103514fba108bdf1d960eeb4c75948cb716cde5c7fb4a".to_string()); // (9-10)
            hashvalues.push("7aa7e388f8145d395ac616bb526eaa35b10069f49e2b36d7327157d1d4af360dfbbfea805aa7e405ed025ce5eadd56c27c40b92991727a5a16b51df5604ad006".to_string()); // 11
            hashvalues.push("b7a5a0f0fb0c4a128b8a3e042fc860775d68d825bb3bf180479d0e12b1884e2652fe51ddb9c991b73824fc15609d82cb1cc19053db7dc7637288091f6027bbce".to_string()); // 12
                                                                                                                                                                            // index 20 ^
            hashvalues.push("354db9c951738783a2d7c8c7301b1aedb4ed469df4b3bfa0368a69ab260ef0087952a7aca45ea67e7cd646aaacff6c9d75b60f194b39e6ad1f194df8b35a27c0".to_string()); // (11-12)
            hashvalues.push("aea22e000365db9566cdab7d709c3c26e738bd41ac1f71cd2e4ad4d6f99e4286801e10d77cdea087b49ad135446130a0a32792250ba28bd211ffb68fe5d04fb0".to_string()); // (9-10)(11-12)
            hashvalues.push("1da541ba91a8560c5dd0c1a4adc836dc4ac96bf5c407a89edb0a49d46de058a713c7b3d3fc8e0324f602c3a41978ef01dccb989eed22aa65bddc5621765713d3".to_string()); // 13
            hashvalues.push("2b789cf44e92c3eacb652124e394b132337fc19378664e376a932723cebf2e0da057319d509a04fe403f2c563542932d1f44476b8f4cad6ccefbd2693c432d1c".to_string()); // 14
            hashvalues.push("e4c46b221c1a82165c03816066af4c9546440705328dd1e419a04a17fbba70a717f67423fe1a553043c51e49cd369f02da979245007a5d09fd6ce0f2cb745491".to_string()); // (13-14)
            hashvalues.push("4a9bb12a4834e77430779ea6759d0f4eb45abb9400a67b81985cd4b85e0a28b5d6b59f896ccc72cd6aad3390b51b02c7d6aeeb8f0dce205f425697e5180b35ae".to_string()); // 15
            hashvalues.push("3346703bc50521b2bf93e8d581605de18ad415c3dcdc38373e37c1800fd332e67c9ef7267d546913b63f5e24324d0c5565c177030d6c30c254d647440191d95f".to_string()); // 16
            hashvalues.push("39495d1ad29c6469ae18bc7316d98977754e0fdbb04a9e3e17c86c34f7fa751e09bbec588e8cfd5d4e55824b9705b1f52ab1a37b5b1fa5c8ea57b0951bdbccf3".to_string()); // (15-16)
            hashvalues.push("77f4a6e8cb87bc79fea9893eeb2dde8a047b0d5786d324a2fb53f43414cfc8051d704f6088102fdf244de046fd5f8ea6cef854dc97488b173a0bb8d540c406ef".to_string()); // (13-14)(15-16)
            hashvalues.push("af3f03f275e586e4449ff44146a27792b0f5a2143483a6dd6fe8405bd66a7ebe13f916d56bd3a152c2a25b6423f8b1bb4620f6d27fe55f1b82da61ff9b0825da".to_string()); // (9-10)(11-12)(13-14)(15-16)
                                                                                                                                                                            // index 30 ^
            hashvalues.push("9a9a504247f809735602e7fdbe191c6129c075f6e1e1530bcfd45ab5e0f1c5974cce5d3eafed04b64b5c881ce369a272f6eca5f403178a51f677aedd6fe66d84".to_string()); // (1-2)(3-4)(5-6)(7-8)(9-10)(11-12)(13-14)(15-16)
            hashvalues.push("5c3f20d14860fb11dca47a3ea972842763165f4cd657608df25fc8afe0cd67666d906cc36b556dccf7d0f9deafbd934fa466391a4f97d03b9fd3cf48f43346ad".to_string()); // 17
            hashvalues.push("2344823c898d803bb0421d8e0e99dafb3feabd3fff02f98a9dae1eabf748c99c6beeb899a65c6a1a83ce60dc8c58332571ccefd11515447d69c73cb4415903a4".to_string()); // 18
            hashvalues.push("a6ff99c73df5c5e9e01b2d6ffd923deba66c1eaa5c60699665c941569b09c756af55aaec9ff8469c7ffe9abd3ca5a3d1ada50ed4ee2cd3ff949177975f4f5141".to_string()); // (17-18)
            hashvalues.push("33a389ba39d39595f2e43650eeaac81187c3a11c56f2930b042325c67adad310dad7ff9ed8077cfb0fa5136a2cfa725e55d567e7dac3483d5fb0ee787a0765ec".to_string()); // 19
            hashvalues.push("92ce61bf50a5c299bc88d6adad5db7b68c4b61abb7760947e8b9898c99312b18ba974d427e1699ede1be7c1c25b03440235a41a71ab2b4d1410399b72da87111".to_string()); // 20
            hashvalues.push("74d84a50748a78c7b98dcc9e22a62d64c726cb0e30126a26d8168e7252f4a67149506a4acde7a307372ebd0a0bcd3ef5f5670434262783d41675448ab7d06e3f".to_string()); // (19-20)
            hashvalues.push("a14d655ecdf12d3dacc2bb9c6779345db9e08fa8ddaa2163ada5d2ff3c21b9bd5b9d59f4f7fbe489543deafd0e2ca45b75d7f7fd047b83e74b85b1ea0a5ec5ff".to_string()); // (17-18)(19-20)
            hashvalues.push("8c715c0b894785852fbc391d662e2131bf0f0c703852f25b1c07429f35dc67ec8df5998acd4cafd4f1ff7019ebfda0877f79d6b91c1b98084efbb7314258608c".to_string()); // 21
            hashvalues.push("3733d5bf4f3d2608ba160adf4a8cddbf545f77b417e3ee3a9e5d3b0afb351579125db853e5bce15d5e82c723f29de1ef294341f0ca3e8b3d3431cec7ac316f34".to_string()); // 22
                                                                                                                                                                            // index 40 ^
            hashvalues.push("77288840877c30ddc8769efac9786505e15729f3a4736996a3b4aed483e896f001acee59b8592ae3d37acbdc60467239dac09bf80a999675b0c2aca058a4003d".to_string()); // (21-22)
            hashvalues.push("08949f758439c6293fe5924defaf3e32bb79b9a93c1331f019c51b386557a9412b27f5a60a80bfa1f524c0d0c2e1f63c5b93d108a9a3af8cdb7fc87c765fca3f".to_string()); // 23

            hashvalues
        }
     

    }
}
