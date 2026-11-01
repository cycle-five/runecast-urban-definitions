//! The one published dump, shared by all requests.

use std::sync::{Arc, RwLock};

use crate::dump::Dump;

#[derive(Default)]
pub struct Definitions {
    dump: RwLock<Option<Arc<Dump>>>,
}

impl Definitions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> Option<Arc<Dump>> {
        self.dump.read().expect("store lock poisoned").clone()
    }

    pub fn publish(&self, dump: Dump) {
        *self.dump.write().expect("store lock poisoned") = Some(Arc::new(dump));
    }
}
