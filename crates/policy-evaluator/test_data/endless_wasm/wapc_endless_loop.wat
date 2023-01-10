;; This is a module meant to be used by a waPC host.
;;
;; This code cheats a little, from the outside it looks like any regular waPC module
;; because it exposes the two functions required by a waPC host. However, these
;; two functions are reduced to the bare mimimum.
;;
;; The most important difference is that no waPC function is registered by the
;; module. Calling any kind of waPC function from the host will result in an
;; endless loop being executed.

(module
  (memory (export "memory") 1)

  ;; waPC host expects a function called wapc_init to be exported
  (func $wapc_init (export "wapc_init")
    ;; we don't do anything in there
    nop
  )

  ;; non exported function that performs an endless loop
  (func $endless_loop
    ;; create a variable and initialize it to 0
    (local $am_i_done i32)

    (loop $endless
      ;; if $am_i_done is not equal to 1 -> go back to the beginning of the loop
      local.get $am_i_done
      i32.const 1
      i32.ne
      br_if $endless
    )
  )

  ;; waPC host expects a function called wapc_init to be exported
  ;; A real implementation would look for the name of the waPC function
  ;; to be invoked, read its payload, invoke the function and
  ;; provide a success/failure boolean as result.
  ;; In this case we just start an endless loop. We don't care about the
  ;; waPC function to be invoked, nor the payload.
  (func $guest_call (export "__guest_call")
    (param $operation_size i32)
    (param $payload_size i32)
    (result i32)
      (call $endless_loop)
      i32.const 0
  )
)
