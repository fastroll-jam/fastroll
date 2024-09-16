#[derive(Clone, Copy)]
pub struct Register {
    pub value: u32,
}

impl Default for Register {
    fn default() -> Self {
        Self { value: 0 }
    }
}
