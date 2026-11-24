//! Host-function gas costs of the GP, which make up the gas usage `g` of each host call.
//!
//! A constant term `M_{X,c}` (or `M_X` alone) is in gas, an octet-linear term `M_{X,l}` in gas per 1024 octets, and a page-linear term in gas per page.

use fr_common::UnsignedGas;
use fr_pvm_types::common::RegValue;

/// `M_∅`: Gas cost of an unknown host call.
pub const UNKNOWN_HOST_CALL_GAS: UnsignedGas = 1000;

/// `M_G`: Gas cost of `gas`.
pub const GAS_GAS: UnsignedGas = 48;
/// `M_{♊,c}`: Base gas cost of `grow_heap`.
pub const GROW_HEAP_BASE_GAS: UnsignedGas = 275;
/// `M_{♊,p}`: Gas cost of `grow_heap` per additional page.
pub const GROW_HEAP_GAS_PER_PAGE: UnsignedGas = 121;
/// `M_{L,c}`: Base gas cost of `lookup`.
pub const LOOKUP_BASE_GAS: UnsignedGas = 600;
/// `M_{L,l}`: Gas cost of `lookup` per 1024 octets.
pub const LOOKUP_GAS_PER_1024_OCTETS: UnsignedGas = 248;
/// `M_{R,c}`: Base gas cost of `read`.
pub const READ_BASE_GAS: UnsignedGas = 2407;
/// `M_{R,k}`: Gas cost of `read` per 1024 octets of the key.
pub const READ_KEY_GAS_PER_1024_OCTETS: UnsignedGas = 1736;
/// `M_{R,v}`: Gas cost of `read` per 1024 octets of the value.
pub const READ_VALUE_GAS_PER_1024_OCTETS: UnsignedGas = 248;
/// `M_{W,c}`: Base gas cost of `write`.
pub const WRITE_BASE_GAS: UnsignedGas = 2442;
/// `M_{W,k}`: Gas cost of `write` per 1024 octets of the key.
pub const WRITE_KEY_GAS_PER_1024_OCTETS: UnsignedGas = 3358;
/// `M_{W,v}`: Gas cost of `write` per 1024 octets of the value.
pub const WRITE_VALUE_GAS_PER_1024_OCTETS: UnsignedGas = 216;
/// `M_I`: Gas cost of `info`.
pub const INFO_GAS: UnsignedGas = 703;

/// `M_{H,c}`: Base gas cost of `historical_lookup`.
pub const HISTORICAL_LOOKUP_BASE_GAS: UnsignedGas = 1125;
/// `M_{H,l}`: Gas cost of `historical_lookup` per 1024 octets.
pub const HISTORICAL_LOOKUP_GAS_PER_1024_OCTETS: UnsignedGas = 264;
/// `M_E`: Gas cost of `export`.
pub const EXPORT_GAS: UnsignedGas = 3521;
/// `M_{M,c}`: Base gas cost of `machine`.
pub const MACHINE_BASE_GAS: UnsignedGas = 1862;
/// `M_{M,l}`: Gas cost of `machine` per 1024 octets of the program.
pub const MACHINE_GAS_PER_1024_OCTETS: UnsignedGas = 112;
/// `M_{P,c}`: Base gas cost of `peek`.
pub const PEEK_BASE_GAS: UnsignedGas = 377;
/// `M_{P,l}`: Gas cost of `peek` per 1024 octets.
pub const PEEK_GAS_PER_1024_OCTETS: UnsignedGas = 336;
/// `M_{O,c}`: Base gas cost of `poke`.
pub const POKE_BASE_GAS: UnsignedGas = 297;
/// `M_{O,l}`: Gas cost of `poke` per 1024 octets.
pub const POKE_GAS_PER_1024_OCTETS: UnsignedGas = 224;
/// `M_{Z,free,c}`: Base gas cost of `pages` for freeing pages.
pub const PAGES_FREE_BASE_GAS: UnsignedGas = 212;
/// `M_{Z,free,p}`: Gas cost of `pages` per freed page.
pub const PAGES_FREE_GAS_PER_PAGE: UnsignedGas = 118;
/// `M_{Z,alloc,c}`: Base gas cost of `pages` for allocating pages.
pub const PAGES_ALLOC_BASE_GAS: UnsignedGas = 275;
/// `M_{Z,alloc,p}`: Gas cost of `pages` per allocated page.
pub const PAGES_ALLOC_GAS_PER_PAGE: UnsignedGas = 121;
/// `M_{Z,setmode,c}`: Base gas cost of `pages` for setting the access mode of allocated pages.
pub const PAGES_SET_MODE_BASE_GAS: UnsignedGas = 130;
/// `M_{Z,setmode,p}`: Gas cost of `pages` per page whose access mode is set.
pub const PAGES_SET_MODE_GAS_PER_PAGE: UnsignedGas = 29;
/// `M_{Z,invalid}`: Gas cost of `pages` with an invalid mode `r`.
pub const PAGES_INVALID_MODE_GAS: UnsignedGas = 80;
/// `M_K`: Base gas cost of `invoke`, charged on top of the gas given to the inner VM.
pub const INVOKE_BASE_GAS: UnsignedGas = 968;
/// `M_X`: Gas cost of `expunge`.
pub const EXPUNGE_GAS: UnsignedGas = 335;

/// `M_{B,c}`: Base gas cost of `bless`.
pub const BLESS_BASE_GAS: UnsignedGas = 422;
/// `M_{B,l}`: Gas cost of `bless` per always-accumulate item.
pub const BLESS_GAS_PER_ITEM: UnsignedGas = 20;
/// `M_A`: Gas cost of `assign`.
pub const ASSIGN_GAS: UnsignedGas = 1818;
/// `M_{D,c}`: Base gas cost of `designate`.
pub const DESIGNATE_BASE_GAS: UnsignedGas = 1100;
/// `M_{D,l}`: Gas cost of `designate` per validator.
pub const DESIGNATE_GAS_PER_VALIDATOR: UnsignedGas = 302;
/// `M_C`: Gas cost of `checkpoint`.
pub const CHECKPOINT_GAS: UnsignedGas = 103;
/// `M_N`: Gas cost of `new`.
pub const NEW_GAS: UnsignedGas = 3855;
/// `M_U`: Gas cost of `upgrade`.
pub const UPGRADE_GAS: UnsignedGas = 1028;
/// `M_T`: Base gas cost of `transfer`, charged on top of the gas limit of a successful transfer.
pub const TRANSFER_BASE_GAS: UnsignedGas = 575;
/// `M_J`: Gas cost of `eject`.
pub const EJECT_GAS: UnsignedGas = 458;
/// `M_Q`: Gas cost of `query`.
pub const QUERY_GAS: UnsignedGas = 643;
/// `M_S`: Gas cost of `solicit`.
pub const SOLICIT_GAS: UnsignedGas = 2193;
/// `M_F`: Gas cost of `forget`.
pub const FORGET_GAS: UnsignedGas = 3250;
/// `M_♉`: Gas cost of `yield`.
pub const YIELD_GAS: UnsignedGas = 98;
/// `M_{♈,c}`: Base gas cost of `provide`.
pub const PROVIDE_BASE_GAS: UnsignedGas = 3980;
/// `M_{♈,l}`: Gas cost of `provide` per 1024 octets.
pub const PROVIDE_GAS_PER_1024_OCTETS: UnsignedGas = 2264;

/// `M_{Y,c}` and `M_{Y,l}` of `fetch` for the data ids 0 to 15, as (base gas, gas per 1024 octets).
const FETCH_GAS_BY_DATA_ID: [(UnsignedGas, UnsignedGas); 16] = [
    (390, 0),
    (103, 0),
    (80, 96),
    (85, 96),
    (85, 96),
    (171, 0),
    (171, 0),
    (85, 96),
    (84, 0),
    (88, 0),
    (111, 0),
    (317, 0),
    (250, 0),
    (95, 96),
    (287, 400),
    (355, 344),
];
/// `M_{Y,∅}`: Gas cost of `fetch` for a data id of 16 or more.
const FETCH_UNKNOWN_DATA_ID_GAS: UnsignedGas = 80;

/// Computes `M(L, ℓ) = ⌈L·ℓ/1024⌉`, the gas for `ℓ` octets at `L` gas per 1024 octets.
///
/// Saturates at `UnsignedGas::MAX`, which no gas counter can cover.
pub fn memory_sized_gas(gas_per_1024_octets: UnsignedGas, size: RegValue) -> UnsignedGas {
    let gas = (gas_per_1024_octets as u128 * size as u128).div_ceil(1024);
    UnsignedGas::try_from(gas).unwrap_or(UnsignedGas::MAX)
}

/// Computes `M_{Y,c} + M(M_{Y,l}, z)`, the gas of `fetch` for the data id `c` (`r10`) and the size `z` (`r9`).
pub fn fetch_gas(data_id: RegValue, size: RegValue) -> UnsignedGas {
    match FETCH_GAS_BY_DATA_ID.get(data_id as usize) {
        Some(&(base_gas, gas_per_1024_octets)) => {
            base_gas.saturating_add(memory_sized_gas(gas_per_1024_octets, size))
        }
        _ => FETCH_UNKNOWN_DATA_ID_GAS,
    }
}

/// Computes the gas of `pages` for the mode `r` (`r10`) and the page count `c` (`r9`).
pub fn pages_gas(mode: RegValue, page_count: RegValue) -> UnsignedGas {
    let (base_gas, gas_per_page) = match mode {
        0 => (PAGES_FREE_BASE_GAS, PAGES_FREE_GAS_PER_PAGE),
        1 | 2 => (PAGES_ALLOC_BASE_GAS, PAGES_ALLOC_GAS_PER_PAGE),
        3 | 4 => (PAGES_SET_MODE_BASE_GAS, PAGES_SET_MODE_GAS_PER_PAGE),
        _ => return PAGES_INVALID_MODE_GAS,
    };
    base_gas.saturating_add(gas_per_page.saturating_mul(page_count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_sized_gas_rounds_up() {
        assert_eq!(memory_sized_gas(248, 0), 0);
        assert_eq!(memory_sized_gas(248, 1), 1);
        assert_eq!(memory_sized_gas(248, 1024), 248);
        assert_eq!(memory_sized_gas(248, 1025), 249);
    }

    #[test]
    fn test_memory_sized_gas_saturates() {
        assert_eq!(
            memory_sized_gas(3358, RegValue::MAX),
            UnsignedGas::MAX,
            "3358·(2^64 - 1)/1024 exceeds 2^64"
        );
    }

    #[test]
    fn test_fetch_gas_by_data_id() {
        assert_eq!(fetch_gas(0, 1 << 20), 390, "no octet-linear term");
        assert_eq!(fetch_gas(14, 1024), 287 + 400);
        assert_eq!(fetch_gas(15, 1), 355 + 1);
        assert_eq!(fetch_gas(16, 1 << 20), 80, "unknown data id");
        assert_eq!(fetch_gas(RegValue::MAX, 1 << 20), 80, "unknown data id");
    }

    #[test]
    fn test_pages_gas_by_mode() {
        assert_eq!(pages_gas(0, 2), 212 + 2 * 118);
        assert_eq!(pages_gas(2, 2), 275 + 2 * 121);
        assert_eq!(pages_gas(4, 2), 130 + 2 * 29);
        assert_eq!(pages_gas(5, 2), 80, "invalid mode");
        assert_eq!(pages_gas(1, RegValue::MAX), UnsignedGas::MAX);
    }
}
