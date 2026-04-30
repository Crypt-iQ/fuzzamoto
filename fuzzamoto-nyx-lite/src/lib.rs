use std::os::raw::{c_char, c_uchar};

unsafe extern "C" {
    pub fn nyx_lite_init() -> usize;
    pub fn nyx_lite_dump_file_to_host(
        file_name: *const c_char,
        file_name_len: usize,
        data: *const c_uchar,
        len: usize,
    );
    pub fn nyx_lite_get_fuzz_input(data: *const c_uchar, max_size: usize) -> usize;
    pub fn nyx_lite_skip();
    pub fn nyx_lite_release();
    pub fn nyx_lite_fail(message: *const c_char);
    pub fn nyx_lite_println(message: *const c_char, size: usize);
}
