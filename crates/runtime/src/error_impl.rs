pub trait WrapError {
    type Output;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: std::fmt::Debug;

    fn tag_location(self) -> Self::Output;
}

impl<T> WrapError for Result<T, Error> {
    type Output = Result<T, Error>;

    fn context<C>(self, context: C) -> Self::Output
    where
        C: std::fmt::Debug,
    {
        match self {
            Ok(value) => Ok(value),
            Err(error) => Err(error.with_context(context)),
        }
    }

    #[track_caller]
    fn tag_location(self) -> Self::Output {
        match self {
            Ok(value) => Ok(value),
            Err(mut error) => {
                error.location = Some(*std::panic::Location::caller());
                Err(error)
            }
        }
    }
}

pub trait ToErrorKind: std::error::Error {
    fn id(&self) -> std::any::TypeId;
}

pub struct Error {
    kind: Box<dyn ToErrorKind>,
    source: Option<Box<dyn std::error::Error>>,
    context: Option<String>,
    location: Option<std::panic::Location<'static>>,
}

unsafe impl Send for Error {}

impl<E> std::cmp::PartialEq<E> for Error
where
    E: ToErrorKind,
{
    fn eq(&self, other: &E) -> bool {
        self.kind.id() == other.id()
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt_kind(f)?;

        self.fmt_source(f)?;

        self.fmt_context(f)?;

        self.fmt_location(f)?;

        Ok(())
    }
}

impl std::error::Error for Error {}

impl<EK> From<EK> for Error
where
    EK: ToErrorKind + 'static,
{
    #[track_caller]
    fn from(value: EK) -> Self {
        Self { kind: Box::new(value), source: None, context: None, location: Some(*std::panic::Location::caller()) }
    }
}

impl From<Error> for String {
    fn from(val: Error) -> Self {
        val.to_string()
    }
}

impl From<Error> for jsonrpsee::types::ErrorObjectOwned {
    fn from(value: Error) -> Self {
        jsonrpsee::types::ErrorObjectOwned::owned::<usize>(
            jsonrpsee::types::error::ErrorCode::InternalError.code(),
            value,
            None,
        )
    }
}

impl Error {
    #[track_caller]
    pub fn new<EK, E>(kind: EK, source: E) -> Self
    where
        EK: ToErrorKind + 'static,
        E: std::error::Error + 'static,
    {
        Self {
            kind: Box::new(kind),
            source: Some(Box::new(source)),
            context: None,
            location: Some(*std::panic::Location::caller()),
        }
    }

    pub fn with_context<C>(mut self, context: C) -> Self
    where
        C: std::fmt::Debug,
    {
        self.context = Some(format!("{:?}", context));
        self
    }

    fn fmt_kind(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.kind)
    }

    fn fmt_source(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => write!(f, " caused by {}", source),
            None => Ok(()),
        }
    }

    fn fmt_context(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.context {
            Some(context) => write!(f, " ({:?})", context),
            None => Ok(()),
        }
    }

    fn fmt_location(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.location {
            Some(location) => write!(f, " at {}:{}", location.file(), location.line()),
            None => Ok(()),
        }
    }
}

mod macros {
    #[macro_export]
    macro_rules! build_error_kind {
        (
            $vis:vis enum $error_kind:ident {
                $($variant:ident = $message:literal,)+
            }
        ) => {
            $crate::paste::paste! {
                $(struct [<$error_kind$variant>];)+

                $vis enum $error_kind {
                    $($variant,)+
                }

                impl std::fmt::Debug for $error_kind {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        write!(f, "{}", self)
                    }
                }

                impl std::fmt::Display for $error_kind {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        match self {
                            $(Self::$variant => write!(f, "[{}]: {}", stringify!($error_kind), $message),)+
                        }
                    }
                }

                impl std::error::Error for $error_kind {}

                impl $crate::error_impl::ToErrorKind for $error_kind {
                    fn id(&self) -> std::any::TypeId {
                        match self {
                            $(Self::$variant => std::any::TypeId::of::<[<$error_kind$variant>]>(),)+
                        }
                    }
                }
            }
        };
    }

    #[macro_export]
    macro_rules! unrecoverable {
        ($error:expr) => {{
            println!("[Panic]: {:?}", $error);
            std::process::exit(1)
        }};
    }
}
