//! Out of band exchange messages.
//!
//! Support for the RFC8183 out-of-band setup requests and responses
//! used to exchange identity and configuration between CAs and their
//! parent CA and/or RPKI Publication Servers.

use std::fmt;
use std::io;
use std::convert::TryFrom;
use std::path::PathBuf;
use std::str::FromStr;
use std::str::from_utf8;
use std::sync::Arc;
use log::debug;
use serde::{
    Deserialize, Serialize, Serializer, Deserializer
};
use crate::repository::x509::Time;
use crate::uri;
use crate::xml;
use crate::xml::decode::{
    Error as XmlError, Name
};
use super::idcert::IdCert;
use super::error::IdExchangeError;

// Constants for the RFC 8183 XML
const VERSION: &str = "1";
const NS: &[u8] = b"http://www.hactrn.net/uris/rpki/rpki-setup/";

const CHILD_REQUEST: Name = Name::qualified(NS, b"child_request");
const CHILD_BPKI_TA: Name = Name::qualified(NS, b"child_bpki_ta");

const PUBLISHER_REQUEST: Name = Name::qualified(NS, b"publisher_request");
const PUBLISHER_BPKI_TA: Name = Name::qualified(NS, b"publisher_bpki_ta");

const PARENT_RESPONSE: Name = Name::qualified(NS, b"parent_response");
const PARENT_BPKI_TA: Name = Name::qualified(NS, b"parent_bpki_ta");
const PARENT_REFERRAL: Name = Name::qualified(NS, b"referral");
const PARENT_OFFER: Name = Name::qualified(NS, b"offer");

const REPOSITORY_RESPONSE: Name = Name::qualified(NS, b"repository_response");
const REPOSITORY_BPKI_TA: Name = Name::qualified(NS, b"repository_bpki_ta");


//------------ Handle --------------------------------------------------------

// Some type aliases that help make the context of Handles more explicit.
pub type ParentHandle = Handle;
pub type ChildHandle = Handle;
pub type PublisherHandle = Handle;
pub type RepositoryHandle = Handle;

/// This type represents the identifying 'handles' as used between RPKI
/// entities. Handles are like strings, but they are restricted to the
/// following - taken from the RELAX NG schema in RFC 8183:
/// 
/// handle  = xsd:string { maxLength="255" pattern="[\-_A-Za-z0-9/]*" }
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(try_from = "String")]
pub struct Handle {
    name: Arc<str>,
}

impl Handle {
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// We replace "/" with "+" and "\" with "=" to make file system
    /// safe names.
    pub fn to_path_buf(&self) -> PathBuf {
        let s = self.to_string();
        let s = s.replace("/", "+");
        let s = s.replace("\\", "=");
        PathBuf::from(s)
    }

    fn verify_name(s: &str) -> Result<(), InvalidHandle> {
        if s.bytes()
            .all(|b| {
                b.is_ascii_alphanumeric() || b == b'-' || b == b'_' ||
                b == b'/' || b == b'\\'
            })
            && !s.is_empty()
            && s.len() < 256
        {
            Ok(())
        } else {
            Err(InvalidHandle)
        }
    }
}

impl TryFrom<&PathBuf> for Handle {
    type Error = InvalidHandle;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        if let Some(path) = path.file_name() {
            let s = path.to_string_lossy().to_string();
            let s = s.replace("+", "/");
            let s = s.replace("=", "\\");
            Self::from_str(&s)
        } else {
            Err(InvalidHandle)
        }
    }
}

impl FromStr for Handle {
    type Err = InvalidHandle;

    /// Accepted pattern: [-_A-Za-z0-9/]{1,255}
    /// See Appendix A of RFC8183.
    ///
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::verify_name(s)?;
        Ok(Handle { name: s.into() })
    }
}

impl TryFrom<String> for Handle {
    type Error = InvalidHandle;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::verify_name(&value)?;
        Ok(Handle { name: value.into() })
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl AsRef<[u8]> for Handle {
    fn as_ref(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Handle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

#[derive(Debug)]
pub struct InvalidHandle;

impl fmt::Display for InvalidHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Handle MUST have pattern: [-_A-Za-z0-9/]{{1,255}}")
    }
}


//------------ ServiceUri ----------------------------------------------------

/// The service URI where a child or publisher needs to send its
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceUri {
    Https(uri::Https),
    Http(String),
}

impl ServiceUri {
    pub fn as_str(&self) -> &str {
        match self {
            ServiceUri::Http(http) => http,
            ServiceUri::Https(https) => https.as_str()
        }
    }
}


impl TryFrom<String> for ServiceUri {
    type Error = IdExchangeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

impl FromStr for ServiceUri {
    type Err = IdExchangeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.to_lowercase().starts_with("http://") {
            Ok(ServiceUri::Http(value.to_string()))
        } else {
            Ok(ServiceUri::Https(uri::Https::from_str(value)?))
        }
    }
}

impl fmt::Display for ServiceUri {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServiceUri::Http(string) => string.fmt(f),
            ServiceUri::Https(https) => https.fmt(f),
        }
    }
}

impl Serialize for ServiceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ServiceUri {
    fn deserialize<D>(deserializer: D) -> Result<ServiceUri, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        ServiceUri::try_from(string).map_err(serde::de::Error::custom)
    }
}

impl AsRef<str> for ServiceUri {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}


//------------ ChildRequest --------------------------------------------------

/// Type representing a <child_request /> defined in section 5.2.1 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChildRequest {
    /// The self-signed IdCert containing the child's public key.
    id_cert: IdCert,

    /// The handle the child wants to use for itself. This may not be honored
    /// by the parent.
    child_handle: ChildHandle,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}


/// # Data Access
///
impl ChildRequest {
    pub fn new(id_cert: IdCert, child_handle: Handle) -> Self {
        ChildRequest {
            id_cert,
            child_handle,
            tag: None,
        }
    }

    pub fn unpack(self) -> (IdCert, ChildHandle, Option<String>) {
        (self.id_cert, self.child_handle, self.tag)
    }
    
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn child_handle(&self) -> &Handle {
        &self.child_handle
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}


/// # XML Support
///
impl ChildRequest {
    /// Parses a <child_request /> message, and validates the
    /// embedded certificate. MUST be a validly signed TA cert.
    pub fn validate<R: io::BufRead>(
        reader: R
    ) -> Result<Self, IdExchangeError> {
        Self::validate_at(reader, Time::now())
    }

    /// Writes the ChildRequest's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer.element(CHILD_REQUEST.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("child_handle", self.child_handle())?
            .opt_attr("tag", self.tag())?
            .content(|content| {
                content
                    .element(CHILD_BPKI_TA.into_unqualified())?
                    .content(|content| {
                        content.base64(self.id_cert.to_captured().as_slice())
                    })?;
                Ok(())
            })?;

        writer.done()
    }

    /// Writes the ChildRequest's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }

    /// Parses a <child_request /> message.
    fn validate_at<R: io::BufRead>(
        reader: R, when: Time
    ) -> Result<Self, IdExchangeError> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut child_handle: Option<ChildHandle> = None;
        let mut tag: Option<String> = None;
        
        let mut outer = reader.start(|element| {
            if element.name() != CHILD_REQUEST {
                return Err(XmlError::Malformed)
            }
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"child_handle" => {
                    child_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(XmlError::Malformed)
            })
        })?;

        let child_handle = child_handle.ok_or(XmlError::Malformed)?;

        // We expect a single element 'child_bpki_ta' to be present which
        // will contain the child id_cert.
        let mut content = outer.take_element(&mut reader, |element| {
            match element.name() {
                CHILD_BPKI_TA => Ok(()),
                _ => Err(XmlError::Malformed)
            }
        })?;

        let id_cert = IdCert::validate_xml_at(
            &mut content,
            &mut reader,
            when
        )?;

        content.take_end(&mut reader)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        Ok(ChildRequest { tag, child_handle, id_cert })
    }
}


//------------ ParentResponse ------------------------------------------------

/// Type representing a <parent_response /> defined in section 5.2.2 of
/// RFC8183.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ParentResponse {
    /// The parent CA's IdCert
    id_cert: IdCert,
    
    /// The handle of the parent CA.
    parent_handle: ParentHandle,
    
    /// The handle chosen for the child CA. Note that this may not be the
    /// same as the handle the CA asked for.
    child_handle: ChildHandle,
    
    /// The URI where the CA needs to send its RFC6492 messages
    service_uri: ServiceUri,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Construct and Data Access
///
impl ParentResponse {
    pub fn new(
        id_cert: IdCert,
        parent_handle: ParentHandle,
        child_handle: ChildHandle,
        service_uri: ServiceUri,
        tag: Option<String>,
    ) -> Self {
        ParentResponse {
            id_cert,
            parent_handle,
            child_handle,
            service_uri,
            tag,
        }
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn parent_handle(&self) -> &ParentHandle {
        &self.parent_handle
    }

    pub fn child_handle(&self) -> &ChildHandle {
        &self.child_handle
    }

    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
/// 
impl ParentResponse {
    /// Parses a <parent_response /> message, and validates the
    /// embedded certificate. MUST be a validly signed TA cert.
    pub fn validate<R: io::BufRead>(
        reader: R
    ) -> Result<Self, IdExchangeError> {
        Self::validate_at(reader, Time::now())
    }


    /// Writes the ParentResponse's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer.element(PARENT_RESPONSE.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("parent_handle", self.parent_handle())?
            .attr("child_handle", self.child_handle())?
            .attr("service_uri", self.service_uri())?
            .opt_attr("tag", self.tag())?
            .content(|content|{
                content
                    .element(PARENT_BPKI_TA.into_unqualified())?
                    .content(|content| {
                        content.base64(self.id_cert.to_captured().as_slice())
                    })?;
                Ok(())
            })?;
        writer.done()
    }


    /// Parses a <parent_response /> message.
    fn validate_at<R: io::BufRead>(
        reader: R, when: Time
    ) -> Result<Self, IdExchangeError> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut child_handle: Option<ChildHandle> = None;
        let mut parent_handle: Option<ParentHandle> = None;
        let mut service_uri: Option<ServiceUri> = None;
        let mut tag: Option<String> = None;
        
        let mut outer = reader.start(|element| {
            if element.name() != PARENT_RESPONSE {
                return Err(XmlError::Malformed)
            }
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"service_uri" => {
                    service_uri = Some(value.ascii_into()?);
                    Ok(())
                }
                b"parent_handle" => {
                    parent_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"child_handle" => {
                    child_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    debug!(
                        "Ignoring attribute in <parent_response />: {:?}",
                        from_utf8(name).unwrap_or("can't parse attr!?")
                    );
                    Ok(())
                }
            })
        })?;

        let service_uri = service_uri.ok_or(XmlError::Malformed)?;
        let parent_handle = parent_handle.ok_or(XmlError::Malformed)?;
        let child_handle = child_handle.ok_or(XmlError::Malformed)?;

        // There can be three different elements:
        //  - parent_bpki_ta
        //  - referral
        //  - offer
        //
        // We only care about the first, we can ignore the others. But,
        // we cannot assume that 'parent_bpki_ta' will be the first element.
        // And we should return an error if we find any other unexpected
        // element here.
        let mut id_cert: Option<IdCert> = None;

        loop {
            let mut bpki_ta_element_found = false;
            let inner = outer.take_opt_element(&mut reader, |element|{
                match element.name() {
                    PARENT_BPKI_TA => {
                        bpki_ta_element_found = true;
                        Ok(())
                    },
                    PARENT_OFFER | PARENT_REFERRAL => {
                        Ok(())
                    },
                    _ => {
                        Err(XmlError::Malformed)
                    }
                }
            })?;
            
            // Break out of loop if we got no element, get the
            // actual element if we can.
            let mut inner = match inner {
                Some(inner) => inner,
                None => break
            };
            
            if bpki_ta_element_found {
                // parse inner text as the ID certificate
                id_cert = Some(IdCert::validate_xml_at(
                    &mut inner,
                    &mut reader,
                    when
                )?);
            } else {
                // skip inner text if there is any (offer does not have any)
                inner.skip_opt_text(&mut reader)?;
            }
            
            inner.take_end(&mut reader)?;
        }

        let id_cert = id_cert.ok_or(XmlError::Malformed)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        Ok(ParentResponse { 
            tag, id_cert, parent_handle, child_handle, service_uri 
        })
    }

    /// Writes the ParentResponse's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }    
}


//------------ PublisherRequest ----------------------------------------------

/// Type representing a <publisher_request/>
///
/// This is the XML message with identity information that a CA sends to a
/// Publication Server.
///
/// For more info, see: https://tools.ietf.org/html/rfc8183#section-5.2.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublisherRequest {
    /// The self-signed IdCert containing the publisher's public key.
    id_cert: IdCert,

    /// The name the publishing CA likes to call itself by
    publisher_handle: PublisherHandle,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Construct and Data Access
///
impl PublisherRequest {
    pub fn new(
        id_cert: IdCert,
        publisher_handle: PublisherHandle,
        tag: Option<String>
    ) -> Self {
        PublisherRequest {
            id_cert,
            publisher_handle,
            tag,
        }
    }

    pub fn unpack(self) -> (IdCert, PublisherHandle, Option<String>) {
        (self.id_cert, self.publisher_handle, self.tag)
    }
    
    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }

    pub fn publisher_handle(&self) -> &Handle {
        &self.publisher_handle
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
/// 
impl PublisherRequest {
    /// Parses a <publisher_request /> message, and validates the
    /// embedded certificate. MUST be a validly signed TA cert.
    pub fn validate<R: io::BufRead>(
        reader: R
    ) -> Result<Self, IdExchangeError> {
        Self::validate_at(reader, Time::now())
    }

    /// Writes the PublisherRequest's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer.element(PUBLISHER_REQUEST.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("publisher_handle", self.publisher_handle())?
            .opt_attr("tag", self.tag())?
            .content(|content| {
                content
                    .element(PUBLISHER_BPKI_TA.into_unqualified())?
                    .content(|content| {
                        content.base64(self.id_cert.to_captured().as_slice())
                    })?;
                Ok(())
            })?;

        writer.done()
    }

    /// Writes the PublisherRequest's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }

    /// Parses a <publisher_request /> message.
    fn validate_at<R: io::BufRead>(
        reader: R, when: Time
    ) -> Result<Self, IdExchangeError> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut publisher_handle: Option<PublisherHandle> = None;
        let mut tag: Option<String> = None;
        
        let mut outer = reader.start(|element| {
            if element.name() != PUBLISHER_REQUEST {
                return Err(XmlError::Malformed)
            }
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"publisher_handle" => {
                    publisher_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => Err(XmlError::Malformed)
            })
        })?;

        let publisher_handle = publisher_handle.ok_or(XmlError::Malformed)?;

        // We expect a single element 'child_bpki_ta' to be present which
        // will contain the child id_cert.
        let mut content = outer.take_element(&mut reader, |element| {
            match element.name() {
                PUBLISHER_BPKI_TA => Ok(()),
                _ => Err(XmlError::Malformed)
            }
        })?;

        let id_cert = IdCert::validate_xml_at(
            &mut content,
            &mut reader,
            when
        )?;

        content.take_end(&mut reader)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        Ok(PublisherRequest { tag, publisher_handle, id_cert })
    }
}


//------------ RepositoryResponse --------------------------------------------

/// Type representing a <repository_response/>
///
/// This is the response sent to a CA by the publication server. It contains
/// the details needed by the CA to send publication messages to the server.
///
/// See https://tools.ietf.org/html/rfc8183#section-5.2.4
#[derive(Clone, Debug, Deserialize, Eq, Serialize, PartialEq)]
pub struct RepositoryResponse {
    /// The Publication Server Identity Certificate
    id_cert: IdCert,
    
    /// The name the publication server decided to call the CA by.
    /// Note that this may not be the same as the handle the CA asked for.
    publisher_handle: PublisherHandle,
    
    /// The URI where the CA needs to send its RFC8181 messages
    service_uri: ServiceUri,
    
    /// Contains the rsync base (sia_base)
    sia_base: uri::Rsync,
    
    /// Contains the RRDP (RFC8182) notification xml uri
    rrdp_notification_uri: Option<uri::Https>,

    /// The optional 'tag' identifier used like a session identifier
    tag: Option<String>,
}

/// # Construct and Data Access
///
impl RepositoryResponse {
    /// Creates a new response.
    pub fn new(
        id_cert: IdCert,
        publisher_handle: Handle,
        service_uri: ServiceUri,
        sia_base: uri::Rsync,
        rrdp_notification_uri: Option<uri::Https>,
        tag: Option<String>,
    ) -> Self {
        RepositoryResponse {
            id_cert,
            publisher_handle,
            service_uri,
            sia_base,
            rrdp_notification_uri,
            tag
        }
    }

    pub fn id_cert(&self) -> &IdCert {
        &self.id_cert
    }
    
    pub fn publisher_handle(&self) -> &Handle {
        &self.publisher_handle
    }
    
    pub fn service_uri(&self) -> &ServiceUri {
        &self.service_uri
    }
    
    pub fn sia_base(&self) -> &uri::Rsync {
        &self.sia_base
    }
    
    pub fn rrdp_notification_uri(&self) -> Option<&uri::Https> {
        self.rrdp_notification_uri.as_ref()
    }

    pub fn tag(&self) -> Option<&String> {
        self.tag.as_ref()
    }
}

/// # XML Support
///
impl RepositoryResponse {
    /// Parses a <repository_response /> message, and validates the
    /// embedded certificate. MUST be a validly signed TA cert.
    pub fn validate<R: io::BufRead>(
        reader: R
    ) -> Result<Self, IdExchangeError> {
        Self::validate_at(reader, Time::now())
    }

    /// Writes the RepositoryResponse's XML representation.
    pub fn write_xml(
        &self, writer: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut writer = xml::encode::Writer::new(writer);

        writer.element(REPOSITORY_RESPONSE.into_unqualified())?
            .attr("xmlns", NS)?
            .attr("version", VERSION)?
            .attr("publisher_handle", self.publisher_handle())?
            .attr("service_uri", self.service_uri())?
            .attr("sia_base", self.sia_base())?
            .opt_attr("rrdp_notification_uri", self.rrdp_notification_uri())?
            .opt_attr("tag", self.tag())?
            .content(|content|{
                content
                    .element(REPOSITORY_BPKI_TA.into_unqualified())?
                    .content(|content| {
                        content.base64(self.id_cert.to_captured().as_slice())
                    })?;
                Ok(())
            })?;
        writer.done()
    }


    /// Parses a <repository_response /> message.
    fn validate_at<R: io::BufRead>(
        reader: R, when: Time
    ) -> Result<Self, IdExchangeError> {
        let mut reader = xml::decode::Reader::new(reader);

        let mut tag: Option<String> = None;
        let mut publisher_handle: Option<PublisherHandle> = None;
        let mut service_uri: Option<ServiceUri> = None;

        let mut sia_base: Option<uri::Rsync>  = None;
        let mut rrdp_notification_uri: Option<uri::Https> = None;

        let mut outer = reader.start(|element| {
            if element.name() != REPOSITORY_RESPONSE {
                return Err(XmlError::Malformed)
            }
            
            element.attributes(|name, value| match name {
                b"version" => {
                    if value.ascii_into::<String>()? != VERSION {
                        return Err(XmlError::Malformed)
                    }
                    Ok(())
                }
                b"service_uri" => {
                    service_uri = Some(value.ascii_into()?);
                    Ok(())
                }
                b"publisher_handle" => {
                    publisher_handle = Some(value.ascii_into()?);
                    Ok(())
                }
                b"sia_base" => {
                    sia_base = Some(value.ascii_into()?);
                    Ok(())
                }
                b"rrdp_notification_uri" => {
                    rrdp_notification_uri = Some(value.ascii_into()?);
                    Ok(())
                }
                b"tag" => {
                    tag = Some(value.ascii_into()?);
                    Ok(())
                }
                _ => {
                    debug!(
                        "Ignoring attribute in <parent_response />: {:?}",
                        from_utf8(name).unwrap_or("can't parse attr!?")
                    );
                    Ok(())
                }
            })
        })?;

        // Check mandatory attributes
        let service_uri = service_uri.ok_or(XmlError::Malformed)?;
        let publisher_handle = publisher_handle.ok_or(XmlError::Malformed)?;
        let sia_base = sia_base.ok_or(XmlError::Malformed)?;

        // We expect a single element 'child_bpki_ta' to be present which
        // will contain the child id_cert.
        let mut content = outer.take_element(&mut reader, |element| {
            match element.name() {
                REPOSITORY_BPKI_TA => Ok(()),
                _ => Err(XmlError::Malformed)
            }
        })?;

        let id_cert = IdCert::validate_xml_at(
            &mut content,
            &mut reader,
            when
        )?;

        content.take_end(&mut reader)?;

        outer.take_end(&mut reader)?;

        reader.end()?;

        Ok(RepositoryResponse { 
            tag,
            publisher_handle,
            id_cert,
            service_uri,
            sia_base,
            rrdp_notification_uri 
        })
    }

    /// Writes the RepositoryResponse's XML representation to a new String.
    pub fn to_xml_string(&self) -> String {
        let mut vec = vec![];
        self.write_xml(&mut vec).unwrap(); // safe
        let xml = from_utf8(vec.as_slice()).unwrap(); // safe

        xml.to_string()
    }
}


//------------ Tests ---------------------------------------------------------

#[cfg(test)]
mod tests {
    
    use super::*;
    
    fn rpkid_time() -> Time {
        Time::utc(2012, 1, 1, 0, 0, 0)
    }

    fn apnic_time() -> Time {
        Time::utc(2020, 3, 3, 0, 0, 0)
    }

    #[test]
    fn child_request_codec() {
        let xml = include_str!("../../test-data/remote/rpkid-child-id.xml");
        let req = ChildRequest::validate_at(
            xml.as_bytes(), rpkid_time()
        ).unwrap();

        assert_eq!(&Handle::from_str("Carol").unwrap(), req.child_handle());
        assert_eq!(None, req.tag());

        let re_encoded_xml = req.to_xml_string();
        let re_decoded = ChildRequest::validate_at(
            re_encoded_xml.as_bytes(),
            rpkid_time()
        ).unwrap();

        assert_eq!(req, re_decoded);
    }

    #[test]
    fn parent_response_codec() {
        let xml = include_str!("../../test-data/remote/apnic-parent-response.xml");
        let req = ParentResponse::validate_at(
            xml.as_bytes(), apnic_time()
        ).unwrap();
        
        let re_encoded_xml = req.to_xml_string();
        let re_decoded = ParentResponse::validate_at(
            re_encoded_xml.as_bytes(),
            apnic_time()
        ).unwrap();

        assert_eq!(req, re_decoded);
    }

    #[test]
    fn parent_response_parse_rpkid_referral() {
        let xml = include_str!("../../test-data/remote/rpkid-parent-response-referral.xml");
        let _req = ParentResponse::validate_at(
            xml.as_bytes(), rpkid_time()
        ).unwrap();
    }

    #[test]
    fn parent_response_parse_rpkid_offer() {
        let xml = include_str!("../../test-data/remote/rpkid-parent-response-offer.xml");
        let _req = ParentResponse::validate_at(
            xml.as_bytes(), rpkid_time()
        ).unwrap();
    }
    
    #[test]
    fn publisher_request_codec() {
        let xml = include_str!("../../test-data/remote/rpkid-publisher-request.xml");
        let req = PublisherRequest::validate_at(
            xml.as_bytes(), rpkid_time()
        ).unwrap();

        let re_encoded_xml = req.to_xml_string();
        let re_decoded = PublisherRequest::validate_at(
            re_encoded_xml.as_bytes(),
            rpkid_time()
        ).unwrap();

        assert_eq!(req, re_decoded);
    }
    
    #[test]
    fn repository_response_codec() {
        let xml = include_str!("../../test-data/remote/apnic-repository-response.xml");
        let req = RepositoryResponse::validate_at(
            xml.as_bytes(), apnic_time()
        ).unwrap();

        let re_encoded_xml = req.to_xml_string();
        let re_decoded = RepositoryResponse::validate_at(
            re_encoded_xml.as_bytes(),
            apnic_time()
        ).unwrap();

        assert_eq!(req, re_decoded);
    }
}
