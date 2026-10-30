//! The one published index, shared by all requests.

use std::sync::{Arc, RwLock};

use crate::index::Index;

#[derive(Default)]
pub struct Definitions {
    index: RwLock<Option<Arc<Index>>>,
}

impl Definitions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> Option<Arc<Index>> {
        self.index.read().expect("store lock poisoned").clone()
    }

    pub fn publish(&self, index: Index) {
        *self.index.write().expect("store lock poisoned") = Some(Arc::new(index));
    }
}
