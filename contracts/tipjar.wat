;; Tip jar: anyone can `deposit` (send value with the call); only the deployer can
;; `withdraw` the whole balance. Ownership is checked against the caller's
;; post-quantum account address.
(module
  (import "env" "storage_read" (func $sread (param i32 i32 i32 i32) (result i32)))
  (import "env" "storage_write" (func $swrite (param i32 i32 i32 i32)))
  (import "env" "caller" (func $caller (param i32)))
  (import "env" "balance" (func $balance (result i64)))
  (import "env" "transfer" (func $transfer (param i32 i64) (result i32)))
  (import "env" "log" (func $log (param i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "owner")
  (data (i32.const 16) "deposit")
  (data (i32.const 32) "withdraw")
  ;; 64..96: caller, 128..160: stored owner
  (func (export "init")
    (call $caller (i32.const 64))
    (call $swrite (i32.const 0) (i32.const 5) (i32.const 64) (i32.const 32)))
  (func (export "deposit")
    (call $log (i32.const 16) (i32.const 7)))
  (func (export "withdraw")
    (call $caller (i32.const 64))
    (drop (call $sread (i32.const 0) (i32.const 5) (i32.const 128) (i32.const 32)))
    (if (i32.or
          (i32.or (i64.ne (i64.load (i32.const 64)) (i64.load (i32.const 128)))
                  (i64.ne (i64.load (i32.const 72)) (i64.load (i32.const 136))))
          (i32.or (i64.ne (i64.load (i32.const 80)) (i64.load (i32.const 144)))
                  (i64.ne (i64.load (i32.const 88)) (i64.load (i32.const 152)))))
      (then unreachable))
    (drop (call $transfer (i32.const 64) (call $balance)))
    (call $log (i32.const 32) (i32.const 8))))
