package oracle

// If included in the wasm compilation this makes the binary too big because
// there's a lot of GRPC shit here
type DecryptionOracle = HttpOracle
