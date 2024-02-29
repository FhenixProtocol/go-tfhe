/* (c) 2023 SCRT Labs. Licensed under Apache-2.0 */

/* Generated with cbindgen:0.24.5 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined(DEFINE_WASM32)
enum ErrnoValue {
  ErrnoValue_Success = 0,
  ErrnoValue_Other = 1,
  ErrnoValue_OutOfGas = 2,
};
typedef int32_t ErrnoValue;
#endif

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
  Op_Div = 5,
  Op_Gt = 6,
  Op_Gte = 7,
  Op_Rem = 8,
  Op_BitAnd = 9,
  Op_BitOr = 10,
  Op_BitXor = 11,
  Op_Eq = 12,
  Op_Ne = 13,
  Op_Min = 14,
  Op_Max = 15,
  Op_Shl = 16,
  Op_Shr = 17,
};
typedef int32_t Op;

enum UnaryOp {
  Not = 0,
};
typedef int32_t UnaryOp;

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
 * Examples have been omitted as they require more dev-dependencies, but you can see them here:
 * https://github.com/CosmWasm/wasmvm/blob/41f7ccd11f0712411619ee16b200924fcd09304e/libwasmvm/src/memory.rs#L4
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

bool generate_full_keys(const char *path_to_cks, const char *path_to_sks, const char *path_to_pks);

struct UnmanagedVector math_operation(struct ByteSliceView lhs,
                                      struct ByteSliceView rhs,
                                      Op operation,
                                      FheUintType uint_type,
                                      struct UnmanagedVector *err_msg);

struct UnmanagedVector unary_math_operation(struct ByteSliceView lhs,
                                            UnaryOp operation,
                                            FheUintType uint_type,
                                            struct UnmanagedVector *err_msg);

struct UnmanagedVector cast_operation(struct ByteSliceView val,
                                      FheUintType from_type,
                                      FheUintType to_type,
                                      struct UnmanagedVector *err_msg);

struct UnmanagedVector cmux(struct ByteSliceView control,
                            struct ByteSliceView if_true,
                            struct ByteSliceView if_false,
                            FheUintType uint_type,
                            struct UnmanagedVector *err_msg);

void load_server_key(struct ByteSliceView key, struct UnmanagedVector *err_msg);

void load_client_key(struct ByteSliceView key, struct UnmanagedVector *err_msg);

void load_public_key(struct ByteSliceView key, struct UnmanagedVector *err_msg);

struct UnmanagedVector get_public_key(struct UnmanagedVector *err_msg);

struct UnmanagedVector expand_compressed(struct ByteSliceView ciphertext,
                                         FheUintType int_type,
                                         struct UnmanagedVector *err_msg);

struct UnmanagedVector trivial_encrypt(uint64_t msg,
                                       FheUintType int_type,
                                       struct UnmanagedVector *err_msg);

struct UnmanagedVector encrypt(uint64_t msg, FheUintType int_type, struct UnmanagedVector *err_msg);

uint64_t decrypt(struct ByteSliceView ciphertext,
                 FheUintType int_type,
                 struct UnmanagedVector *err_msg);

struct UnmanagedVector new_unmanaged_vector(bool nil, const uint8_t *ptr, uintptr_t length);

void destroy_unmanaged_vector(struct UnmanagedVector v);

/**
 * Returns a version number of this library as a C string.
 *
 * The string is owned by the lib and must not be mutated or destroyed by the caller.
 */
const char *version(void);

void init_logger(void);
