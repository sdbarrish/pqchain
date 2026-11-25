// Adapted from Winterfell's examples (MIT License, Copyright (c) Facebook, Inc. and its affiliates;
// see LICENSE-winterfell). Aggregate example and the `Example` trait removed.

pub mod threshold;

pub mod signature;
pub use signature::{message_to_elements, PrivateKey, Signature};

pub use crate::utils::rescue::{self, CYCLE_LENGTH, NUM_ROUNDS as NUM_HASH_ROUNDS};
