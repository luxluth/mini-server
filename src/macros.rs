#[macro_export]
macro_rules! response_from_for {
    ($from:ty => $to:ty) => {
        impl From<$from> for $to {
            fn from(value: $from) -> Self {
                let mut resp = Self::default();
                resp.set_body(value.into());
                resp
            }
        }
    };
}
