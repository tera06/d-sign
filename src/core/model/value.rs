#[derive(Copy, Clone, PartialEq, Debug)]
pub struct ShareIndex(usize);

impl ShareIndex {
    pub fn new(index: usize) -> Self {
        Self(index)
    }
    pub fn get(&self) -> usize {
        self.0
    }
}
