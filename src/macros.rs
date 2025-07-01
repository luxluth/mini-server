#[macro_export]
macro_rules! response_from_for {
    ($for:ty) => {
        impl Into<$crate::HTTPResponse> for $for {
            fn into(self) -> $crate::HTTPResponse {
                let mut resp = $crate::HTTPResponse::default();
                resp.set_body(self.into());
                resp
            }
        }
    };
}
