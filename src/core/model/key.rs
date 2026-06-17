use crate::core::model::{
    signature::{Digest, Signature, SignatureShare},
    value::ShareIndex,
};
pub struct PublicKey<T> {
    pub public_key: T,
}

pub struct SecretKey<T> {
    num_key_shares: usize,
    secret_key: T,
}
pub struct SecretKeyShare<T> {
    pub index: ShareIndex,
    pub secret_key_share: T,
}
pub trait Verifiable {
    type TSignature;
    type TDigest;
    type TError: std::error::Error;

    fn verify(
        &self,
        signature: &Signature<Self::TSignature>,
        digest: &Digest<Self::TDigest>,
    ) -> Result<bool, Self::TError>;
}

pub trait Divisible {
    type TSecretKeyShare;
    type TError: std::error::Error;
    fn divide(
        &self,
        num_divide: usize,
    ) -> Result<Vec<SecretKeyShare<Self::TSecretKeyShare>>, Self::TError>;
}
pub trait Signable {
    type TDigest;
    type TSignatureShare;
    type TError: std::error::Error;

    fn sign(
        &self,
        index: ShareIndex,
        digest: &Digest<Self::TDigest>,
    ) -> Result<SignatureShare<Self::TSignatureShare>, Self::TError>;
}

pub trait CombineSignatureShares {
    type TSignatureShare;
    type TSignature;
    type TError: std::error::Error;

    fn combine_signature_shares(
        &self,
        signature_shares: &[SignatureShare<Self::TSignatureShare>],
    ) -> Result<Signature<Self::TSignature>, Self::TError>;
}

impl<T> PublicKey<T>
where
    T: Verifiable + CombineSignatureShares,
{
    pub fn new(public_key: T) -> Self {
        Self { public_key }
    }

    pub fn verify(
        &self,
        signature: &Signature<<T as Verifiable>::TSignature>,
        digest: &Digest<T::TDigest>,
    ) -> Result<bool, <T as Verifiable>::TError> {
        self.public_key.verify(signature, digest)
    }

    pub fn combine_signature_shares(
        &self,
        signature_shares: &[SignatureShare<<T as CombineSignatureShares>::TSignatureShare>],
    ) -> Result<
        Signature<<T as CombineSignatureShares>::TSignature>,
        <T as CombineSignatureShares>::TError,
    > {
        self.public_key.combine_signature_shares(signature_shares)
    }
}

impl<T> SecretKey<T>
where
    T: Divisible,
{
    pub fn new(threshold: usize, num_key_shares: usize, secret_key: T) -> Option<Self> {
        if threshold == 0 || num_key_shares == 0 {
            return None;
        }
        if threshold > num_key_shares {
            return None;
        }

        Some(Self {
            num_key_shares,
            secret_key,
        })
    }
    pub fn divide(&self) -> Result<Vec<SecretKeyShare<T::TSecretKeyShare>>, T::TError> {
        self.secret_key.divide(self.num_key_shares)
    }
}

impl<T> SecretKeyShare<T>
where
    T: Signable,
{
    pub fn new(index: ShareIndex, secret_key_share: T) -> Self {
        Self {
            index,
            secret_key_share,
        }
    }

    pub fn sign(
        &self,
        digest: &Digest<T::TDigest>,
    ) -> Result<SignatureShare<T::TSignatureShare>, T::TError> {
        self.secret_key_share.sign(self.index, digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{
        signature::{Digest, Signature, SignatureShare},
        value::ShareIndex,
    };
    use mockall::{mock, predicate::*};
    use thiserror::Error;

    #[derive(Error, Debug, PartialEq)]
    pub enum MockError {
        #[error("Failed to verify")]
        Verify,
        #[error("Failed to combine signature shares")]
        CombineSignatureShares,
        #[error("Failed to divide")]
        Divide,
        #[error("Failed to sign")]
        Sign,
    }
    mock! {
        pub VerifiableCombinableKey{}

        impl Verifiable for VerifiableCombinableKey {
            type TSignature = u32;
            type TDigest = u32;
            type TError = MockError;

            fn verify(
                &self,
                signature: &Signature<u32>,
                digest: &Digest<u32>,
            ) -> Result<bool, MockError>;
        }

        impl CombineSignatureShares for VerifiableCombinableKey {
            type TSignatureShare = u32;
            type TSignature = u32;
            type TError = MockError;

            fn combine_signature_shares(
                &self,
                signature_shares: &[SignatureShare<u32>],
            ) -> Result<Signature<u32>, MockError>;
        }
    }

    mock! {
        pub DivisibleKey{}

        impl Divisible for DivisibleKey {
            type TSecretKeyShare = MockSignableShare;
            type TError = MockError;

            fn divide(
                &self,
                num_divide: usize,
            ) -> Result<Vec<SecretKeyShare<MockSignableShare>>, MockError>;
        }
    }

    mock! {
        pub SignableShare{}

        impl Signable for SignableShare {
            type TDigest = u32;
            type TSignatureShare = u32;
            type TError = MockError;

            fn sign(
                &self,
                index: ShareIndex,
                digest: &Digest<u32>,
            ) -> Result<SignatureShare<u32>, MockError>;
        }
    }

    #[test]
    fn test_public_key_verify_call_verify() {
        let mut mock = MockVerifiableCombinableKey::new();
        mock.expect_verify().times(1).returning(|_, _| Ok(true));

        let public_key = PublicKey::new(mock);
        let signature = Signature::new(10);
        let digest = Digest::new(10);

        let result = public_key.verify(&signature, &digest).unwrap();
        assert!(result);
    }

    #[test]
    fn test_public_key_verify_return_error_if_internal_verify_failed() {
        let mut mock = MockVerifiableCombinableKey::new();
        mock.expect_verify()
            .times(1)
            .returning(|_, _| Err(MockError::Verify));

        let public_key = PublicKey::new(mock);
        let signature = Signature::new(10);
        let digest = Digest::new(10);

        let result = public_key.verify(&signature, &digest);

        let err = result.err().unwrap();
        assert_eq!(err, MockError::Verify);
    }

    #[test]
    fn test_public_key_combine_signature_shares_call_combine_signature_shares() {
        let mut mock = MockVerifiableCombinableKey::new();
        mock.expect_combine_signature_shares()
            .times(1)
            .returning(|_| Ok(Signature::new(10)));

        let public_key = PublicKey::new(mock);

        let signature_shares = vec![
            SignatureShare::new(ShareIndex::new(1), 10),
            SignatureShare::new(ShareIndex::new(2), 10),
        ];
        let result = public_key
            .combine_signature_shares(&signature_shares)
            .unwrap();
        assert_eq!(result.signature, 10)
    }

    #[test]
    fn test_public_key_combine_signature_shares_return_error_if_internal_combine_signature_shares_failed()
     {
        let mut mock = MockVerifiableCombinableKey::new();
        mock.expect_combine_signature_shares()
            .times(1)
            .returning(|_| Err(MockError::CombineSignatureShares));

        let public_key = PublicKey::new(mock);

        let signature_shares = vec![
            SignatureShare::new(ShareIndex::new(1), 10),
            SignatureShare::new(ShareIndex::new(2), 10),
        ];
        let result = public_key.combine_signature_shares(&signature_shares);
        let err = result.err().unwrap();

        assert_eq!(err, MockError::CombineSignatureShares);
    }

    #[test]
    fn test_secret_key_created_in_threshold_less_num_key_shares() {
        let mock = MockDivisibleKey::new();
        let secret_key = SecretKey::new(1, 2, mock);
        assert!(secret_key.is_some());
    }
    #[test]
    fn test_secret_key_created_in_threshold_equal_num_key_shares() {
        let mock = MockDivisibleKey::new();
        let secret_key = SecretKey::new(1, 1, mock);
        assert!(secret_key.is_some());
    }

    #[test]
    fn test_secret_key_not_created_in_threshold_is_zero() {
        let mock = MockDivisibleKey::new();
        let secret_key = SecretKey::new(0, 1, mock);
        assert!(secret_key.is_none());
    }
    #[test]
    fn test_secret_key_not_created_in_num_key_shares_is_zero() {
        let mock = MockDivisibleKey::new();
        let secret_key = SecretKey::new(1, 0, mock);
        assert!(secret_key.is_none());
    }

    #[test]
    fn test_secret_key_not_created_in_threshold_greater_num_key_shares() {
        let mock = MockDivisibleKey::new();
        let secret_key = SecretKey::new(2, 1, mock);
        assert!(secret_key.is_none());
    }

    #[test]
    fn test_secret_key_divide_call_divide() {
        let mut mock = MockDivisibleKey::new();
        mock.expect_divide().times(1).returning(|_| {
            Ok(vec![
                SecretKeyShare::new(ShareIndex::new(1), MockSignableShare::new()),
                SecretKeyShare::new(ShareIndex::new(2), MockSignableShare::new()),
            ])
        });

        let secret_key = SecretKey::new(1, 2, mock).unwrap();
        let result = secret_key.divide().unwrap();
        assert_eq!(result[0].index, ShareIndex::new(1));
        assert_eq!(result[1].index, ShareIndex::new(2));
    }

    #[test]
    fn test_secret_key_divide_return_error_if_internal_divide_failed() {
        let mut mock = MockDivisibleKey::new();
        mock.expect_divide()
            .times(1)
            .returning(|_| Err(MockError::Divide));

        let secret_key = SecretKey::new(1, 2, mock).unwrap();
        let result = secret_key.divide();
        let err = result.err().unwrap();

        assert_eq!(err, MockError::Divide);
    }

    #[test]
    fn test_secret_key_share_sign_call_sign() {
        let mut mock = MockSignableShare::new();
        mock.expect_sign()
            .times(1)
            .returning(|_, _| Ok(SignatureShare::new(ShareIndex::new(1), 100)));

        let secret_key_share = SecretKeyShare::new(ShareIndex::new(1), mock);
        let digest = Digest::new(100);
        let result = secret_key_share.sign(&digest).unwrap();
        assert_eq!(result.index, ShareIndex::new(1));
        assert_eq!(result.signature_share, 100);
    }

    #[test]
    fn test_secret_key_share_sign_return_error_if_internal_sign_failed() {
        let mut mock = MockSignableShare::new();
        mock.expect_sign()
            .times(1)
            .returning(|_, _| Err(MockError::Sign));
        let secret_key_share = SecretKeyShare::new(ShareIndex::new(1), mock);
        let digest = Digest::new(100);
        let result = secret_key_share.sign(&digest);

        let err = result.err().unwrap();
        assert_eq!(err, MockError::Sign);
    }
}
