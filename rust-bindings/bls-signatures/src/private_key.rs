use std::ffi::c_void;

use bls_dash_sys::{
    CoreMPLDeriveChildSk, CoreMPLDeriveChildSkUnhardened, CoreMPLKeyGen, PrivateKeyFree,
    PrivateKeyFromBytes, PrivateKeyFromSeedBIP32, PrivateKeyGetG1Element, PrivateKeyIsEqual,
    PrivateKeySerialize,
};

use crate::{
    schemes::Scheme,
    utils::{c_err_to_result, SecureBox},
    BlsError, G1Element,
};

pub const PRIVATE_KEY_SIZE: usize = 32; // TODO somehow extract it from bls library

#[derive(Debug)]
pub struct PrivateKey {
    pub(crate) c_private_key: *mut c_void,
}

impl PartialEq for PrivateKey {
    fn eq(&self, other: &Self) -> bool {
        unsafe { PrivateKeyIsEqual(self.c_private_key, other.c_private_key) }
    }
}

impl Eq for PrivateKey {}

impl PrivateKey {
    pub(crate) fn as_mut_ptr(&self) -> *mut c_void {
        self.c_private_key
    }

    // TODO Rename to from_seed
    pub fn key_gen(scheme: &impl Scheme, seed: &[u8]) -> Result<Self, BlsError> {
        Ok(PrivateKey {
            c_private_key: c_err_to_result(|did_err| unsafe {
                CoreMPLKeyGen(
                    scheme.as_mut_ptr(),
                    seed.as_ptr() as *const _,
                    seed.len(),
                    did_err,
                )
            })?,
        })
    }

    pub fn g1_element(&self) -> Result<G1Element, BlsError> {
        Ok(G1Element {
            c_element: c_err_to_result(|did_err| unsafe {
                PrivateKeyGetG1Element(self.c_private_key, did_err)
            })?.into(),
        })
    }

    pub fn serialize(&self) -> SecureBox {
        // `PrivateKeySerialize` internally securely allocates memory which we have to
        // wrap safely
        unsafe {
            SecureBox::from_ptr(
                PrivateKeySerialize(self.c_private_key) as *mut u8,
                PRIVATE_KEY_SIZE,
            )
        }
    }

    pub fn from_bytes(bytes: &[u8], mod_order: bool) -> Result<Self, BlsError> {
        if bytes.len() != PRIVATE_KEY_SIZE {
            return Err(BlsError {
                msg: format!(
                    "Private key size must be {}, got {}",
                    PRIVATE_KEY_SIZE,
                    bytes.len()
                ),
            });
        }

        let c_private_key = c_err_to_result(|did_err| unsafe {
            PrivateKeyFromBytes(bytes.as_ptr() as *const c_void, mod_order, did_err)
        })?;

        Ok(PrivateKey { c_private_key })
    }

    pub fn from_bip32_seed(bytes: &[u8]) -> Self {
        let c_private_key = unsafe { PrivateKeyFromSeedBIP32(bytes.as_ptr() as *const c_void) };

        PrivateKey { c_private_key }
    }

    pub fn derive_child_private_key(&self, scheme: &impl Scheme, index: u32) -> PrivateKey {
        PrivateKey {
            c_private_key: unsafe {
                CoreMPLDeriveChildSk(scheme.as_mut_ptr(), self.c_private_key, index)
            },
        }
    }

    pub fn derive_child_private_key_unhardened(
        &self,
        scheme: &impl Scheme,
        index: u32,
    ) -> PrivateKey {
        PrivateKey {
            c_private_key: unsafe {
                CoreMPLDeriveChildSkUnhardened(scheme.as_mut_ptr(), self.c_private_key, index)
            },
        }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe { PrivateKeyFree(self.c_private_key) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schemes::AugSchemeMPL;

    #[test]
    fn serialize_deserialize() {
        let seed = b"seedweedseedweedseedweedseedweed";
        let scheme = AugSchemeMPL::new();
        let sk1 = PrivateKey::key_gen(&scheme, seed).expect("unable to generate private key");
        let sk1_bytes = sk1.serialize();
        let sk2 = PrivateKey::from_bytes(sk1_bytes.as_slice(), false)
            .expect("cannot build private key from bytes");

        assert_eq!(sk1, sk2);
    }

    #[test]
    fn should_return_private_key_from_bip32_bytes() {
        let bytes = [1, 2, 3, 4, 5, 6, 7];

        let private_key = PrivateKey::from_bip32_seed(&bytes);

        let expected_key_bytes = [
            0, 40, 43, 250, 83, 117, 227, 93, 174, 67, 170, 185, 235, 46, 70, 117, 110, 208, 224,
            23, 164, 13, 180, 200, 132, 46, 57, 21, 207, 149, 248, 135,
        ];

        assert_eq!(*private_key.serialize(), expected_key_bytes);
    }
}
