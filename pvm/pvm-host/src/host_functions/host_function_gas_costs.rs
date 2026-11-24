//! Host-function gas costs of the GP, which make up the gas usage `g` of each host call.

use fr_common::UnsignedGas;

/// `M_{♊,c}`: Base gas cost of `grow_heap`.
pub const GROW_HEAP_BASE_GAS: UnsignedGas = 100;
/// `M_{♊,p}`: Gas cost of `grow_heap` per additional page.
pub const GROW_HEAP_GAS_PER_PAGE: UnsignedGas = 10;
