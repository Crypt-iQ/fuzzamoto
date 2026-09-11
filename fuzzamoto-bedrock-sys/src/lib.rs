//! Low-level bindings to fuzzamoto's bedrock guest agent.
//!
//! The bedrock counterpart to [`fuzzamoto-nyx-sys`]. See
//! `fuzzamoto-bedrock-sys/src/bedrock-agent.c` for what each call does on the
//! wire; the short version is that one shared buffer and one hypercall
//! (`HYPERCALL_FUZZ_NEXT_INPUT`) carry both the testcase and its result.
//!
//! [`fuzzamoto-nyx-sys`]: ../fuzzamoto_nyx_sys/index.html

use std::os::raw::{c_char, c_uchar};

// Exposed bedrock agent functions.
//
// See docs in `fuzzamoto-bedrock-sys/src/bedrock-agent.c`
unsafe extern "C" {
    /// Register the fuzz-input buffer and signal boot complete. Returns the
    /// maximum input size the harness may receive.
    pub fn bedrock_init() -> usize;
    /// Fetch the next testcase. The host checkpoints the VM here, so on a
    /// forked VM this is where execution resumes.
    pub fn bedrock_get_fuzz_input(data: *mut c_uchar, max_size: usize) -> usize;
    /// Report that this testcase was unusable; it should not be counted.
    pub fn bedrock_skip();
    /// Report that this testcase completed cleanly, ending the execution.
    pub fn bedrock_release();
    /// Report that the harness detected a bug.
    pub fn bedrock_fail(message: *const c_char);
    /// Emit a line to the host's serial event stream.
    pub fn bedrock_println(message: *const c_char, size: usize);
    /// Hand a file to the host. Returns 0 on success, -1 on failure; failure is
    /// non-fatal, so callers may ignore it.
    pub fn bedrock_dump_file_to_host(
        name: *const c_char,
        name_len: usize,
        data: *const c_uchar,
        len: usize,
    ) -> i32;
}
