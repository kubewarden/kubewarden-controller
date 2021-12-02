#[derive(Clone)]
pub(crate) struct SigstoreOpts {
    pub fulcio_cert: Vec<u8>,
    pub rekor_public_key: String,
}
