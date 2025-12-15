(module
  (func $endless_loop (export "endless_loop")
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
  (start $endless_loop)
)
