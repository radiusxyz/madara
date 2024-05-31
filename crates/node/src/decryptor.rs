fn main() -> Result<(), madara_runtime::error_impl::Error> {
    madara_runtime::subprocess::run_process::<mc_transaction_pool::decryptor::DecryptEncryptedTransaction>()?;
    Ok(())
}
