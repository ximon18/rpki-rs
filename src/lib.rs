//! All things RPKI.
//!
//! The _Resource Public Key Infrastructure_ (RPKI) is an application of
//! PKI to Internet routing security. It allows owners of IP address prefixes
//! and AS numbers to publish cryptographically signed information about
//! these resources. In particular, RPKI is currently used for route origin
//! validation where these statements list the AS numbers that are allowed
//! to originate routes for prefixes.
//!
//! More information on RPKI in general can be found at the
//! [RPKI Documentation Project](https://rpki.readthedocs.io/).
//!
//! This crate implements low-level functionality necessary to produce,
//! collect, and validate RPKI data. It is not by itself enough to create an
//! RPKI validator or an RPKI CA. For the former, you might want to have a
//! look at [Routinator](https://github.com/NLnetLabs/routinator) which can
//! be used as a library crate and form the basis for special-purpose RPKI
//! relying party software.
//!
//! The crate consists of modules for all supported the PRKI objects:
//!
//! * resource certificates in [cert](cert/index.html),
//! * certificate revocation lists (CRLs) in [crl](crl/index.html),
//! * manifests in [manifest](manifest/index.html), and
//! * ROAs [roa](roa/index.html).
//!
//! Manifests and ROAs are based on a profile of CMS signed data called a
//! signed object which can be found in the [sigobj](sigobj/index.html)
//! module.
//!
//! The crate currently does not support ghostbuster records and router
//! certificates.
//!
//! Some additional modules are used by these objects such as
//! [crypto](crypto/index.html) that provides all the signature-releated
//! functionality or [x509](x509/index.html) with various things needed by
//! certificates and CRLs.
//!
//! The [rrdp](rrdp/index.html) module provides the low-level functionality
//! the RRDP protocol for distributing RPKI data.

// We have seemingly redundant closures (i.e., closures where just providing
// a function would also work) that cannot be removed due to lifetime issues.
// (This has since been corrected but is still present in 1.34.0.)
#![allow(clippy::redundant_closure)]

pub mod cert;
pub mod crl;
pub mod crypto;
pub mod csr;
pub mod manifest;
pub mod oid;
pub mod resources;
pub mod roa;
pub mod rrdp;
pub mod sigobj;
pub mod tal;
pub mod uri;
pub mod x509;
pub mod xml;

mod util;
