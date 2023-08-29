/* (c) 2023 SCRT Labs. Licensed under Apache-2.0 */

/* Generated with cbindgen:0.24.5 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

enum ErrnoValue {
  ErrnoValue_Success = 0,
  ErrnoValue_Other = 1,
  ErrnoValue_OutOfGas = 2,
};
typedef int32_t ErrnoValue;

enum FheUintType {
  FheUintType_Uint8 = 0,
  FheUintType_Uint16 = 1,
  FheUintType_Uint32 = 2,
};
typedef int32_t FheUintType;

enum Op {
  Op_Add = 0,
  Op_Sub = 1,
  Op_Mul = 2,
  Op_Lt = 3,
  Op_Lte = 4,
};
typedef int32_t Op;

/**
 * An optional Vector type that requires explicit creation and destruction
 * and can be sent via FFI.
 * It can be created from `Option<Vec<u8>>` and be converted into `Option<Vec<u8>>`.
 *
 * This type is always created in Rust and always dropped in Rust.
 * If Go code want to create it, it must instruct Rust to do so via the
 * [`new_unmanaged_vector`] FFI export. If Go code wants to consume its data,
 * it must create a copy and instruct Rust to destroy it via the
 * [`destroy_unmanaged_vector`] FFI export.
 *
 * An UnmanagedVector is immutable.
 *
 * ## Ownership
 *
 * Ownership is the right and the obligation to destroy an `UnmanagedVector`
 * exactly once. Both Rust and Go can create an `UnmanagedVector`, which gives
 * then ownership. Sometimes it is necessary to transfer ownership.
 *
 * ### Transfer ownership from Rust to Go
 *
 * When an `UnmanagedVector` was created in Rust using [`UnmanagedVector::new`], [`UnmanagedVector::default`]
 * or [`new_unmanaged_vector`], it can be passted to Go as a return value (see e.g. [load_wasm][crate::load_wasm]).
 * Rust then has no chance to destroy the vector anymore, so ownership is transferred to Go.
 * In Go, the data has to be copied to a garbage collected `[]byte`. Then the vector must be destroyed
 * using [`destroy_unmanaged_vector`].
 *
 * ### Transfer ownership from Go to Rust
 *
 * When Rust code calls into Go (using the vtable methods), return data or error messages must be created
 * in Go. This is done by calling [`new_unmanaged_vector`] from Go, which copies data into a newly created
 * `UnmanagedVector`. Since Go created it, it owns it. The ownership is then passed to Rust via the
 * mutable return value pointers. On the Rust side, the vector is destroyed using [`UnmanagedVector::consume`].
 *
 * ## Examples
 *
 * Transferring ownership from Rust to Go using return values of FFI calls:
 *
 * ```
 * # use wasmvm::{cache_t, ByteSliceView, UnmanagedVector};
 * #[no_mangle]
 * pub extern "C" fn save_wasm_to_cache(
 *     cache: *mut cache_t,
 *     wasm: ByteSliceView,
 *     error_msg: Option<&mut UnmanagedVector>,
 * ) -> UnmanagedVector {
 *     # let checksum: Vec<u8> = Default::default();
 *     // some operation producing a `let checksum: Vec<u8>`
 *
 *     UnmanagedVector::new(Some(checksum)) // this unmanaged vector is owned by the caller
 * }
 * ```
 *
 * Transferring ownership from Go to Rust using return value pointers:
 *
 * ```rust
 * # use cosmwasm_vm::{BackendResult, GasInfo};
 * # use wasmvm::{Db, GoError, U8SliceView, UnmanagedVector};
 * fn db_read(db: &Db, key: &[u8]) -> BackendResult<Option<Vec<u8>>> {
 *
 *     // Create a None vector in order to reserve memory for the result
 *     let mut output = UnmanagedVector::default();
 *
 *     // …
 *     # let mut error_msg = UnmanagedVector::default();
 *     # let mut used_gas = 0_u64;
 *
 *     let go_error: GoError = (db.vtable.read_db)(
 *         db.state,
 *         db.gas_meter,
 *         &mut used_gas as *mut u64,
 *         U8SliceView::new(Some(key)),
 *         // Go will create a new UnmanagedVector and override this address
 *         &mut output as *mut UnmanagedVector,
 *         &mut error_msg as *mut UnmanagedVector,
 *     )
 *     .into();
 *
 *     // We now own the new UnmanagedVector written to the pointer and must destroy it
 *     let value = output.consume();
 *
 *     // Some gas processing and error handling
 *     # let gas_info = GasInfo::free();
 *
 *     (Ok(value), gas_info)
 * }
 * ```
 *
 *
 * If you want to mutate data, you need to comsume the vector and create a new one:
 *
 * ```rust
 * # use wasmvm::{UnmanagedVector};
 * # let input = UnmanagedVector::new(Some(vec![0xAA]));
 * let mut mutable: Vec<u8> = input.consume().unwrap_or_default();
 * assert_eq!(mutable, vec![0xAA]);
 *
 * // `input` is now gone and we cam do everything we want to `mutable`,
 * // including operations that reallocate the underylying data.
 *
 * mutable.push(0xBB);
 * mutable.push(0xCC);
 *
 * assert_eq!(mutable, vec![0xAA, 0xBB, 0xCC]);
 *
 * let output = UnmanagedVector::new(Some(mutable));
 *
 * // `output` is ready to be passed around
 * ```
 */
typedef struct UnmanagedVector {
  /**
   * True if and only if this is None. If this is true, the other fields must be ignored.
   */
  bool is_none;
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} UnmanagedVector;

/**
 * A view into an externally owned byte slice (Go `[]byte`).
 * Use this for the current call only. A view cannot be copied for safety reasons.
 * If you need a copy, use [`ByteSliceView::to_owned`].
 *
 * Go's nil value is fully supported, such that we can differentiate between nil and an empty slice.
 */
typedef struct ByteSliceView {
  /**
   * True if and only if the byte slice is nil in Go. If this is true, the other fields must be ignored.
   */
  bool is_nil;
  const uint8_t *ptr;
  uintptr_t len;
} ByteSliceView;

struct UnmanagedVector math_operation(struct ByteSliceView lhs,
                                      struct ByteSliceView rhs,
                                      Op operation,
                                      FheUintType uint_type,
                                      struct UnmanagedVector *err_msg);

bool deserialize_server_key(struct ByteSliceView key, struct UnmanagedVector *err_msg);

bool deserialize_client_key(struct ByteSliceView key, struct UnmanagedVector *err_msg);

bool deserialize_public_key(struct ByteSliceView key, struct UnmanagedVector *err_msg);

struct UnmanagedVector get_public_key(struct UnmanagedVector *err_msg);

struct UnmanagedVector expand_compressed(struct ByteSliceView ciphertext,
                                         FheUintType int_type,
                                         struct UnmanagedVector *err_msg);

struct UnmanagedVector encrypt(uint64_t msg, FheUintType int_type, struct UnmanagedVector *err_msg);

struct UnmanagedVector trivial_encrypt(uint64_t msg,
                                       FheUintType int_type,
                                       struct UnmanagedVector *err_msg);

uint64_t decrypt(struct ByteSliceView ciphertext,
                 FheUintType int_type,
                 struct UnmanagedVector *err_msg);

bool generate_full_keys(const char *path_to_cks, const char *path_to_sks, const char *path_to_pks);

struct UnmanagedVector new_unmanaged_vector(bool nil, const uint8_t *ptr, uintptr_t length);

void destroy_unmanaged_vector(struct UnmanagedVector v);

/**
 * Returns a version number of this library as a C string.
 *
 * The string is owned by the lib and must not be mutated or destroyed by the caller.
 */
const char *version_str(void);
