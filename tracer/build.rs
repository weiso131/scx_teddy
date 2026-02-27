fn main() {
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_skel("src/bpf/tracer.bpf.c", "bpf")
        .compile_link_gen()
        .unwrap();
}
