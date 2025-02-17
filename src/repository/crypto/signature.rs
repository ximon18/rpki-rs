//! Signature algorithms and operations.

use bcder::{decode, encode};
use bcder::encode::PrimitiveContent;
use bcder::{Oid, Tag};
use bytes::Bytes;
use super::super::oid;
use super::keys::PublicKeyFormat;


//------------ SignatureAlgorithm --------------------------------------------

/// The signature algorihms used by RPKI.
///
/// These are the algorithms used for creating and verifying signatures. For
/// RPKI, [RFC 7935] allows only one algorithm, RSA PKCS #1 v1.5 with
/// SHA-256. However, there are two possible representations of the
/// non-existant algorithm parameters. In certain circumstances, it is
/// imporant that these two representations do not compare as equal.
/// Therefore, this type keeps track of the representation used.
///
/// Should additional algorithms be introduced into RPKI, this type will be
/// adjusted accordingly.
///
/// You can construct the signature algorithm currently preferred for RPKI
/// via the `Default` implementation.
///
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SignatureAlgorithm {
    /// Is the parameter field present?
    ///
    /// If `true`, then a parameter field is present and NULL. Otherwise it
    /// is missing.
    ///
    /// Constructed values will always have this set to `true`.
    has_parameter: bool
}

impl SignatureAlgorithm {
    /// Returns the preferred public key format for this algorithm.
    pub fn public_key_format(self) -> PublicKeyFormat {
        PublicKeyFormat::Rsa
    }
}


/// # ASN.1 Values
///
/// Signature algorithm identifiers appear in certificates and other objects
/// from [RFC 5280] (simply as algorithm identifiers) as well as in signed
/// objects.
///
/// ```txt
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// AlgorithmIdentifier          ::= SEQUENCE {
///      algorithm                   OBJECT IDENTIFIER,
///      parameters                  ANY DEFINED BY algorithm OPTIONAL }
/// ```
///
/// Currently, [RFC 7935] allows only one algorithm, but sadly it uses
/// different identifiers in different places. For X.509-related objects,
/// i.e., certificates, CRLs, and certification requests, this is
/// `sha256WithRSAEncryption` from [RFC 4055].  For signed objects, the
/// identifier must be `rsaEncryption` from [RFC 3370] for constructed
/// objects while both must be accepted when reading objects.
///
/// Because of these differences, you’ll find two sets of functions and
/// methods in this section. Those prefixed with `x509` deal with the
/// X.509-related identifiers while `cms_` is the prefix for signed objects.
///
/// The parameters field for the former identifier can be either NULL or
/// missing and must be NULL for the latter. We will, however, accept an
/// absent field for the latter as well. In both cases, the returned value
/// will remember whether there was a parameters field. Values with and
/// without parameters will not compare equal.
///
/// When constructing identifiers, we will always include a parameters field
/// and set it to NULL, independently of what the value says.
///
/// [RFC 3370]: https://tools.ietf.org/html/rfc3370
/// [RFC 4055]: https://tools.ietf.org/html/rfc4055
/// [RFC 7935]: https://tools.ietf.org/html/rfc7935
impl SignatureAlgorithm {
    /// Takes a signature algorithm identifier for X.509 objects.
    ///
    /// Returns a malformed error if the algorithm isn’t the allowed for RPKI
    /// or if it isn’t correctly encoded.
    pub fn x509_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::x509_from_constructed)
    }

    /// Parses the algorithm identifier for X.509 objects.
    fn x509_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        oid::SHA256_WITH_RSA_ENCRYPTION.skip_if(cons)?;
        let has_parameter = cons.take_opt_primitive_if(
            Tag::NULL, |_| Ok(())
        )?.is_some();
        Ok(SignatureAlgorithm { has_parameter })
    }

    /// Takes a signature algorithm identifier for CMS objects.
    ///
    /// Returns a malformed error if the algorithm isn’t the allowed for RPKI
    /// or if it isn’t correctly encoded.
    pub fn cms_take_from<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        cons.take_sequence(Self::cms_from_constructed)
    }

    /// Parses the algorithm identifier for CMS objects.
    fn cms_from_constructed<S: decode::Source>(
        cons: &mut decode::Constructed<S>
    ) -> Result<Self, S::Err> {
        let oid = Oid::take_from(cons)?;
        if oid != oid::RSA_ENCRYPTION && oid != oid::SHA256_WITH_RSA_ENCRYPTION
        {
            return Err(decode::Malformed.into())
        }
        let has_parameter = cons.take_opt_primitive_if(
            Tag::NULL, |_| Ok(())
        )?.is_some();
        Ok(SignatureAlgorithm { has_parameter })
    }

    /// Provides an encoder for X.509 objects.
    pub fn x509_encode(self) -> impl encode::Values {
        encode::sequence((
            oid::SHA256_WITH_RSA_ENCRYPTION.encode(),
            ().encode(),
        ))
    }

    /// Provides an encoder for CMS objects.
    pub fn cms_encode(self) -> impl encode::Values {
        encode::sequence((
            oid::RSA_ENCRYPTION.encode(),
            ().encode(),
        ))
    }
}


//--- Default

impl Default for SignatureAlgorithm {
    fn default() -> Self {
        SignatureAlgorithm { has_parameter: true }
    }
}


//------------ Signature -----------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature {
    algorithm: SignatureAlgorithm,
    value: Bytes
}

impl Signature {
    pub fn new(algorithm: SignatureAlgorithm, value: Bytes) -> Self {
        Signature { algorithm, value }
    }

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    pub fn value(&self) -> &Bytes {
        &self.value
    }

    pub fn unwrap(self) -> (SignatureAlgorithm, Bytes) {
        (self.algorithm, self.value)
    }
}