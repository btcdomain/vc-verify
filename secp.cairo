from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.constants import N0, N1, N2, BASE
from starkware.cairo.common.cairo_secp.ec import EcPoint, ec_add, ec_mul
from starkware.cairo.common.cairo_secp.signature import div_mod_n, validate_signature_entry, get_generator_point


// # Secp256k1 ECDSA signature.
func verify_ecdsa{range_check_ptr}(
        public_key_pt : EcPoint, msg_hash : BigInt3, r : BigInt3, s : BigInt3) {
    alloc_locals;

    validate_signature_entry(r);
    validate_signature_entry(s);

    let gen_pt = get_generator_point();

    // # Compute u1 and u2.
    let (u1 : BigInt3) = div_mod_n(msg_hash, s);
    let (u2 : BigInt3) = div_mod_n(r, s);

    let (gen_u1) = ec_mul(gen_pt.point, u1);
    let (pub_u2) = ec_mul(public_key_pt, u2);
    let (res) = ec_add(gen_u1, pub_u2);

    assert res.x = r;
    return ();
}
