//! Data size checks during evaluation.
#![cfg(not(feature = "unchecked"))]

use super::GlobalRuntimeState;
use crate::types::dynamic::Union;
use crate::{Dynamic, Engine, Position, RhaiResultOf, ERR};
use std::borrow::Borrow;
#[cfg(feature = "no_std")]
use std::prelude::v1::*;

/// Recursively calculate the sizes of an array.
///
/// Sizes returned are `(` [`Array`][crate::Array], [`Map`][crate::Map] and [`String`] `)`.
///
/// # Panics
///
/// Panics if any interior data is shared (should never happen).
#[cfg(not(feature = "no_index"))]
#[inline]
pub fn calc_array_sizes(array: &crate::Array) -> (usize, usize, usize) {
    let (mut ax, mut mx, mut sx) = (0, 0, 0);

    for value in array {
        ax += 1;

        match value.0 {
            Union::Array(ref a, ..) => {
                let (a, m, s) = calc_array_sizes(a);
                ax += a;
                mx += m;
                sx += s;
            }
            Union::Blob(ref a, ..) => ax += 1 + a.len(),
            #[cfg(not(feature = "no_object"))]
            Union::Map(ref m, ..) => {
                let (a, m, s) = calc_map_sizes(m);
                ax += a;
                mx += m;
                sx += s;
            }
            Union::Str(ref s, ..) => sx += s.len(),
            #[cfg(not(feature = "no_closure"))]
            Union::Shared(..) => {
                unreachable!("shared values discovered within data")
            }
            _ => (),
        }
    }

    (ax, mx, sx)
}
/// Recursively calculate the sizes of a map.
///
/// Sizes returned are `(` [`Array`][crate::Array], [`Map`][crate::Map] and [`String`] `)`.
///
/// # Panics
///
/// Panics if any interior data is shared (should never happen).
#[cfg(not(feature = "no_object"))]
#[inline]
pub fn calc_map_sizes(map: &crate::Map) -> (usize, usize, usize) {
    let (mut ax, mut mx, mut sx) = (0, 0, 0);

    for value in map.values() {
        mx += 1;

        match value.0 {
            #[cfg(not(feature = "no_index"))]
            Union::Array(ref a, ..) => {
                let (a, m, s) = calc_array_sizes(a);
                ax += a;
                mx += m;
                sx += s;
            }
            #[cfg(not(feature = "no_index"))]
            Union::Blob(ref a, ..) => ax += 1 + a.len(),
            Union::Map(ref m, ..) => {
                let (a, m, s) = calc_map_sizes(m);
                ax += a;
                mx += m;
                sx += s;
            }
            Union::Str(ref s, ..) => sx += s.len(),
            #[cfg(not(feature = "no_closure"))]
            Union::Shared(..) => {
                unreachable!("shared values discovered within data")
            }
            _ => (),
        }
    }

    (ax, mx, sx)
}

/// Recursively calculate the sizes of a value.
///
/// Sizes returned are `(` [`Array`][crate::Array], [`Map`][crate::Map] and [`String`] `)`.
///
/// # Panics
///
/// Panics if any interior data is shared (should never happen).
#[inline]
pub fn calc_data_sizes(value: &Dynamic, _top: bool) -> (usize, usize, usize) {
    match value.0 {
        #[cfg(not(feature = "no_index"))]
        Union::Array(ref arr, ..) => calc_array_sizes(arr),
        #[cfg(not(feature = "no_index"))]
        Union::Blob(ref blob, ..) => (blob.len(), 0, 0),
        #[cfg(not(feature = "no_object"))]
        Union::Map(ref map, ..) => calc_map_sizes(map),
        Union::Str(ref s, ..) => (0, 0, s.len()),
        #[cfg(not(feature = "no_closure"))]
        Union::Shared(..) if _top => calc_data_sizes(&value.read_lock::<Dynamic>().unwrap(), true),
        #[cfg(not(feature = "no_closure"))]
        Union::Shared(..) => {
            unreachable!("shared values discovered within data: {}", value)
        }
        _ => (0, 0, 0),
    }
}

/// (provable-harness patch) Meter units per array or map element, map entry or
/// curried value: walking one costs about 16x as many zkVM cycles as a string
/// byte.
pub const ELEMENT_WEIGHT: usize = 16;

/// (provable-harness patch) Meter units per native function call. A call costs
/// about as many zkVM cycles as 64 string bytes, also when a native function
/// calls another one (`contains`, `==` on arrays, `sort`), which no operation
/// counter sees.
pub const CALL_WEIGHT: usize = 64;

/// (provable-harness patch) Meter units per array, map, BLOB or function
/// pointer: cloning or dropping one allocates or frees, about 1000 zkVM cycles
/// (nested arrays, or arrays of small maps, cost that per element).
pub const CONTAINER_WEIGHT: usize = 96;

/// (provable-harness patch) Meter units for walking a value (`strings`), or for
/// cloning it (strings are reference-counted, so cloning them is O(1)): string
/// bytes, elements, map keys (copied by a clone) and the curried values of
/// function pointers, which Rhai's own size checks skip. A shared value inside
/// another one (a closure's captured variable) is a reference-counted pointer:
/// it counts as one element and is not followed, so reference cycles end.
pub(crate) fn meter_units(value: &Dynamic, strings: bool) -> usize {
    match value.0 {
        #[cfg(not(feature = "no_closure"))]
        Union::Shared(..) => value
            .read_lock::<Dynamic>()
            .map_or(ELEMENT_WEIGHT, |v| meter_units_inner(&v, strings)),
        _ => meter_units_inner(value, strings),
    }
}

fn meter_units_inner(value: &Dynamic, strings: bool) -> usize {
    let each = |v: &Dynamic| ELEMENT_WEIGHT + meter_units_inner(v, strings);
    match value.0 {
        Union::Str(ref s, ..) if strings => s.len(),
        #[cfg(not(feature = "no_index"))]
        Union::Array(ref a, ..) => CONTAINER_WEIGHT + a.iter().map(each).sum::<usize>(),
        #[cfg(not(feature = "no_index"))]
        Union::Blob(ref b, ..) => CONTAINER_WEIGHT + b.len(),
        #[cfg(not(feature = "no_object"))]
        Union::Map(ref m, ..) => {
            CONTAINER_WEIGHT + m.iter().map(|(k, v)| k.len() + each(v)).sum::<usize>()
        }
        Union::FnPtr(ref f, ..) => CONTAINER_WEIGHT + f.curry().iter().map(each).sum::<usize>(),
        #[cfg(not(feature = "no_closure"))]
        Union::Shared(..) => ELEMENT_WEIGHT,
        _ => 0,
    }
}

impl Engine {
    /// (provable-harness patch) Charge `units` to the data-volume meter.
    #[inline]
    pub(crate) fn track_data_volume(&self, units: usize, pos: Position) -> RhaiResultOf<()> {
        if let Some(meter) = self.data_volume.as_ref() {
            if let Some(token) = meter(units as u64) {
                return Err(ERR::ErrorTerminated(token, pos).into());
            }
        }
        Ok(())
    }

    /// (provable-harness patch) Charge the full size of a value.
    #[inline]
    pub(crate) fn track_value_volume(&self, value: &Dynamic, pos: Position) -> RhaiResultOf<()> {
        if self.data_volume.is_none() {
            return Ok(());
        }
        self.track_data_volume(1 + meter_units(value, true), pos)
    }

    /// (provable-harness patch) Charge a value about to be cloned.
    #[inline]
    pub(crate) fn track_clone_volume(&self, value: &Dynamic, pos: Position) -> RhaiResultOf<()> {
        if self.data_volume.is_none() {
            return Ok(());
        }
        self.track_data_volume(meter_units(value, false), pos)
    }

    /// (provable-harness patch) Charge curried values about to be cloned.
    #[inline]
    pub(crate) fn track_curry_volume(&self, curry: &[Dynamic], pos: Position) -> RhaiResultOf<()> {
        if self.data_volume.is_none() || curry.is_empty() {
            return Ok(());
        }
        let units = curry
            .iter()
            .map(|v| ELEMENT_WEIGHT + meter_units(v, false))
            .sum::<usize>();
        self.track_data_volume(units, pos)
    }

    /// (provable-harness patch) Charge a native function call and its arguments.
    #[inline]
    pub(crate) fn track_args_volume(&self, args: &[&mut Dynamic], pos: Position) -> RhaiResultOf<()> {
        if self.data_volume.is_none() {
            return Ok(());
        }
        let units = args.iter().map(|v| meter_units(v, true)).sum::<usize>();
        self.track_data_volume(CALL_WEIGHT + units, pos)
    }

    /// Raise an error if any data size exceeds limit.
    ///
    /// [`Position`] in [`EvalAltResult`][crate::EvalAltResult] is always [`NONE`][Position::NONE]
    /// and should be set afterwards.
    #[cfg(not(feature = "unchecked"))]
    pub(crate) fn throw_on_size(&self, (_arr, _map, s): (usize, usize, usize)) -> RhaiResultOf<()> {
        if self.limits.string_len.map_or(false, |max| s > max.get()) {
            return Err(
                ERR::ErrorDataTooLarge("Length of string".to_string(), Position::NONE).into(),
            );
        }

        #[cfg(not(feature = "no_index"))]
        if self.limits.array_size.map_or(false, |max| _arr > max.get()) {
            return Err(
                ERR::ErrorDataTooLarge("Size of array/BLOB".to_string(), Position::NONE).into(),
            );
        }

        #[cfg(not(feature = "no_object"))]
        if self.limits.map_size.map_or(false, |max| _map > max.get()) {
            return Err(
                ERR::ErrorDataTooLarge("Size of object map".to_string(), Position::NONE).into(),
            );
        }

        Ok(())
    }

    /// Check whether the size of a [`Dynamic`] is within limits.
    #[cfg(not(feature = "unchecked"))]
    #[inline]
    pub(crate) fn check_data_size<T: Borrow<Dynamic>>(
        &self,
        value: T,
        pos: Position,
    ) -> RhaiResultOf<T> {
        // (provable-harness patch) Every checked result is metered.
        self.track_value_volume(value.borrow(), pos)?;

        // If no data size limits, just return
        if !self.has_data_size_limit() {
            return Ok(value);
        }

        let sizes = calc_data_sizes(value.borrow(), true);

        self.throw_on_size(sizes)
            .map_err(|err| err.fill_position(pos))?;

        Ok(value)
    }

    /// Raise an error if the size of a [`Dynamic`] is out of limits (if any).
    ///
    /// Not available under `unchecked`.
    #[cfg(not(feature = "unchecked"))]
    #[inline(always)]
    pub fn ensure_data_size_within_limits(&self, value: &Dynamic) -> RhaiResultOf<()> {
        self.check_data_size(value, Position::NONE).map(|_| ())
    }

    /// Check if the number of operations stay within limit.
    #[inline(always)]
    pub(crate) fn track_operation(
        &self,
        global: &mut GlobalRuntimeState,
        pos: Position,
    ) -> RhaiResultOf<()> {
        let mut num_ops = None;

        let mut num_operations = || {
            *num_ops.get_or_insert_with(|| {
                // Increment operations count
                #[cfg(atomic_ops_count)]
                return global
                    .num_operations
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;

                #[cfg(not(atomic_ops_count))]
                {
                    global.num_operations += 1;
                    return global.num_operations;
                }
            })
        };

        // Guard against too many operations
        #[cfg(not(feature = "unchecked"))]
        if self.max_operations() > 0 && num_operations() > self.max_operations() {
            return Err(ERR::ErrorTooManyOperations(pos).into());
        }

        if let Some(progress) = self.progress.as_ref() {
            return progress(num_operations())
                .map(|token| Err(ERR::ErrorTerminated(token, pos).into()))
                .unwrap_or(Ok(()));
        }

        Ok(())
    }
}
