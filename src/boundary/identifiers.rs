use crate::boundary::errors::BoundaryError;

macro_rules! declare_bounded_id {
    ($name:ident, $max_len:expr, $err_msg:expr, |$char_binder:ident| $validation:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
        pub struct $name(String);

        impl TryFrom<String> for $name {
            type Error = BoundaryError;

            fn try_from(raw: String) -> Result<Self, Self::Error> {
                if raw.is_empty() || raw.len() > $max_len {
                    return Err(BoundaryError::InvalidIdentifier($err_msg.into()));
                }
                if !raw.chars().all(|$char_binder| $validation) {
                    return Err(BoundaryError::InvalidIdentifier($err_msg.into()));
                }
                Ok(Self(raw))
            }
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

macro_rules! declare_exact_hex_id {
    ($name:ident, $exact_len:expr, $err_msg:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
        pub struct $name(String);

        impl TryFrom<String> for $name {
            type Error = BoundaryError;

            fn try_from(raw: String) -> Result<Self, Self::Error> {
                if raw.len() != $exact_len || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(BoundaryError::InvalidCryptographicFormat($err_msg.into()));
                }
                Ok(Self(raw))
            }
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

declare_bounded_id!(ManifestId, 64, "Invalid ManifestId format", |c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
declare_bounded_id!(SessionId, 64, "Invalid SessionId format", |c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
declare_bounded_id!(ApprovalId, 64, "Invalid ApprovalId format", |c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
declare_bounded_id!(ApprovalIssuerId, 64, "Invalid ApprovalIssuerId format", |c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
declare_bounded_id!(ActorId, 128, "Invalid ActorId format", |c| c.is_ascii_alphanumeric() || c == '@' || c == '.' || c == '_' || c == '-');
declare_bounded_id!(TicketReference, 128, "Invalid TicketReference format", |c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == ':' || c == '/');

declare_exact_hex_id!(ManifestHash, 64, "ManifestHash must be exactly 64 hex characters");
declare_exact_hex_id!(InvocationHash, 64, "InvocationHash must be exactly 64 hex characters");
declare_exact_hex_id!(ApprovalSignature, 128, "ApprovalSignature must be exactly 128 hex characters");
