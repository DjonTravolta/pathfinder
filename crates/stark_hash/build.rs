use std::env;
use std::fs;
use std::path::Path;

use stark_curve::*;

fn generate_consts(path: &Path, bits: u32) {
    let buf = &mut String::with_capacity(10 * 1024 * 1024);

    buf.push_str(&format!(
        "pub const CURVE_CONSTS_BITS: usize = {};\n\n",
        bits
    ));

    push_points(buf, "P1", &PEDERSEN_P1, 248, bits);
    buf.push_str("\n\n\n");
    push_points(buf, "P2", &PEDERSEN_P2, 4, bits);
    buf.push_str("\n\n\n");
    push_points(buf, "P3", &PEDERSEN_P3, 248, bits);
    buf.push_str("\n\n\n");
    push_points(buf, "P4", &PEDERSEN_P4, 4, bits);

    fs::write(path, buf).expect("Unable to write file");
}

fn push_points(buf: &mut String, name: &str, base: &ProjectivePoint, max_bits: u32, bits: u32) {
    let base = AffinePoint::from(base);

    let full_chunks = max_bits / bits;
    let leftover_bits = max_bits % bits;
    let table_size_full = (1 << bits) - 1;
    let table_size_leftover = (1 << leftover_bits) - 1;
    let len = full_chunks * table_size_full + table_size_leftover;

    buf.push_str(&format!(
        "pub const CURVE_CONSTS_{}: [AffinePoint; {}] = [\n",
        name, len
    ));

    let mut bits_left = max_bits;
    let mut outer_point = base;
    while bits_left > 0 {
        let eat_bits = std::cmp::min(bits_left, bits);
        let table_size = (1 << eat_bits) - 1;

        println!("Processing {} bits, remaining: {}", eat_bits, bits_left);

        // Loop through each possible bit combination except zero
        let mut inner_point = outer_point.clone();
        for j in 1..(table_size + 1) {
            if bits_left < max_bits || j > 1 {
                buf.push_str(",\n");
            }
            push_point(buf, &inner_point);
            inner_point.add(&outer_point);
        }

        // Shift outer point #bits times
        bits_left -= eat_bits;
        for _i in 0..bits {
            outer_point.double();
        }
    }

    buf.push_str("\n];");
}

fn push_point(buf: &mut String, p: &AffinePoint) {
    let x = p.x.inner();
    let y = p.y.inner();
    buf.push_str("    AffinePoint::new(");
    buf.push_str("\n        [");
    buf.push_str(&format!("\n            {},", x[0]));
    buf.push_str(&format!("\n            {},", x[1]));
    buf.push_str(&format!("\n            {},", x[2]));
    buf.push_str(&format!("\n            {},", x[3]));
    buf.push_str("\n        ],");
    buf.push_str("\n        [");
    buf.push_str(&format!("\n            {},", y[0]));
    buf.push_str(&format!("\n            {},", y[1]));
    buf.push_str(&format!("\n            {},", y[2]));
    buf.push_str(&format!("\n            {},", y[3]));
    buf.push_str("\n        ]");
    buf.push_str("\n    )");
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("curve_consts.rs");
    let bits = 4;
    generate_consts(&dest_path, bits);
}
