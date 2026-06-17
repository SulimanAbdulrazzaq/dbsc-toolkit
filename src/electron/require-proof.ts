// Electron runs a Node main process, so the per-request guard is exactly the
// raw-http one. Re-export it under an Electron-flavored type alias.
export { requireProof, type NodeProofGuard as ElectronProofGuard } from "../node/require-proof.js";
