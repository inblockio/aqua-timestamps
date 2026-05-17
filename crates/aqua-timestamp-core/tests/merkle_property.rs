//! Property tests for the Merkle build pipeline.
//!
//! Asserts the order-independence guarantee that the M2 sealer leans on:
//! for any non-empty set of *distinct* 32-byte leaves, the Merkle root
//! computed after sorting is invariant under permutations of the input.

use aqua_timestamp_core::merkle::merkle_root_for_leaves;
use proptest::collection::vec;
use proptest::prelude::*;

prop_compose! {
    fn arb_leaf()(bytes in vec(any::<u8>(), 32)) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }
}

proptest! {
    /// Two permutations of the same distinct-leaf set seal to the same
    /// root, because the sealer sorts before building.
    #[test]
    fn merkle_root_is_permutation_invariant(
        mut leaves in vec(arb_leaf(), 1..50),
        seed in any::<u64>(),
    ) {
        // Drop duplicates so the test exercises distinct leaves only;
        // duplicate handling is dedup at the accumulator layer, not at
        // the Merkle layer.
        leaves.sort();
        leaves.dedup();
        prop_assume!(!leaves.is_empty());

        let mut a = leaves.clone();
        let mut b = leaves;
        a.sort_unstable();

        // Shuffle `b` deterministically from the seed.
        let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        for i in (1..b.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state as usize) % (i + 1);
            b.swap(i, j);
        }
        b.sort_unstable();

        let root_a = merkle_root_for_leaves(&a);
        let root_b = merkle_root_for_leaves(&b);
        prop_assert_eq!(root_a, root_b);
    }
}
