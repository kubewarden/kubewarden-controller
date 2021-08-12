enum Runtime {
    Wapc(wapc::WapcHost),
    // The `BurregoEvaluator` variant is boxed since it outsizes the
    // other variants of this enum.
    Burrego(Box<BurregoEvaluator>),
}
