pub trait Configs: Sized {
    fn load() -> Result<Self, Box<dyn std::error::Error>>;
}
