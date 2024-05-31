use std::any::{self, Any};
use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::error::BuilderRuntimeError;
use crate::error_impl::{Error, WrapError};

type Value = Box<dyn Any + Send + Sync + 'static>;

/// Represents a thread-safe context for storing and retrieving arbitrary data by string keys.
///
/// Data is stored as a boxed `Any` trait object, which can store any type that implements `Any`.
pub struct Context {
    inner: Arc<Mutex<HashMap<&'static str, Value>>>,
}

impl Clone for Context {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl Default for Context {
    /// Creates an empty `Context`.
    fn default() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::default())) }
    }
}

impl Context {
    /// Asynchronously stores a value in the context associated with a given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to associate with the value.
    /// * `value` - The value to be stored.
    ///
    /// # Examples
    ///
    /// ```
    /// // Assuming usage within an async block.
    /// runtime::context().store("my_key", my_value).await;
    /// ```
    pub async fn store<V>(&self, key: &'static str, value: V)
    where
        V: Clone + Send + Sync + 'static,
    {
        let value_any: Value = Box::new(value);

        let mut lock = self.inner.lock().await;

        lock.insert(key, value_any);
    }

    /// Asynchronously retrieves a value from the context by key and tries to downcast it to the
    /// desired type.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to be retrieved.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The key does not exist.
    /// * The stored value cannot be downcasted to the desired type.
    ///
    /// # Examples
    ///
    /// ```
    /// // Assuming usage within an async block.
    /// let value: MyValue = runtime::context().load("my_key").await.unwrap();
    /// ```
    pub async fn load<V>(&self, key: impl AsRef<str>) -> Result<V, Error>
    where
        V: Clone + Send + Sync + 'static,
    {
        let lock = self.inner.lock().await;

        let value_any = lock
            .get(key.as_ref())
            .ok_or(Error::from(BuilderRuntimeError::NoneType))
            .context(format_args!("key: {:?}", key.as_ref()))?;

        match value_any.downcast_ref::<V>() {
            Some(value) => Ok(value.clone()),
            None => {
                Err(Error::from(BuilderRuntimeError::Downcast)
                    .with_context(format_args!("{:?}", any::type_name::<V>())))
            }
        }
    }

    /// Stores a value in the context associated with a given key in a blocking manner.
    ///
    /// This function is a synchronous version of the `store` method.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to associate with the value.
    /// * `value` - The value to be stored.
    ///
    /// # Examples
    ///
    /// ```
    /// runtime::context().store_blocking("my_key", my_value);
    /// ```
    pub fn store_blocking<V>(&self, key: &'static str, value: V)
    where
        V: Clone + Send + Sync + 'static,
    {
        let value_any: Value = Box::new(value);

        let mut lock = self.inner.blocking_lock();

        lock.insert(key, value_any);
    }

    /// Retrieves a value from the context by key in a blocking manner and tries to downcast it to
    /// the desired type.
    ///
    /// This function is a synchronous version of the `load` method.
    ///
    /// # Arguments
    ///
    /// * `key` - The key associated with the value to be retrieved.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The key does not exist.
    /// * The stored value cannot be downcasted to the desired type.
    ///
    /// # Examples
    ///
    /// ```
    /// let value: MyValue = runtime::context().load_blocking("my_key").unwrap();
    /// ```
    pub fn load_blocking<V>(&self, key: impl AsRef<str>) -> Result<V, Error>
    where
        V: Clone + Send + Sync + 'static,
    {
        let lock = self.inner.blocking_lock();

        let value_any = lock
            .get(key.as_ref())
            .ok_or(Error::from(BuilderRuntimeError::NoneType))
            .context(format_args!("key: {:?}", key.as_ref()))?;

        match value_any.downcast_ref::<V>() {
            Some(value) => Ok(value.clone()),
            None => {
                Err(Error::from(BuilderRuntimeError::Downcast)
                    .with_context(format_args!("{:?}", any::type_name::<V>())))
            }
        }
    }
}
