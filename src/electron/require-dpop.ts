// DPoP guard is request/response-based like the rest; re-export the node one.
export { requireDpop, type NodeDpopGuard as ElectronDpopGuard } from "../node/require-dpop.js";
