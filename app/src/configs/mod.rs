use std::env;

pub trait Configs: Sized {
    fn load() -> Result<Self, env::VarError>;
}
