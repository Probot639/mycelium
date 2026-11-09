use crate::corpus::hash_bytes;

/// Reduce sanitizer or libFuzzer output to a stable per-bug signature: the error
/// class plus the top stack frames, with volatile addresses and offsets dropped.
/// Two crashing inputs that hit the same bug produce the same signature, so the
/// coordinator can group them.
///
/// Also handles common non-sanitizer crash messages (glibc stack protector, heap
/// corruption) so that QEMU-mode fuzzing without ASAN still gets useful dedup.
pub fn stack_signature(output: &str) -> String {
    let mut kind = String::new();
    let mut kind_is_sanitizer = false;
    let mut frames: Vec<String> = Vec::new();

    for line in output.lines() {
        // ASAN/libFuzzer markers always override a glibc/signal tag that
        // appeared on an earlier line, because they carry a more specific
        // error class. glibc's __stack_chk_fail prints "stack smashing
        // detected" then calls abort(); ASAN's signal handler fires after
        // that, so without this precedence the less-informative tag sticks.
        if !kind_is_sanitizer {
            // Check specific sanitizer prefixes before the generic
            // "Sanitizer: " substring, so LeakSanitizer gets a real kind
            // instead of the word after the colon ("detected").
            if let Some(i) = line.find("LeakSanitizer: ") {
                let _ = i;
                kind = "memory-leak".to_string();
                kind_is_sanitizer = true;
            } else {
                for marker in ["Sanitizer: ", "libFuzzer: "] {
                    if let Some(i) = line.find(marker) {
                        let after = &line[i + marker.len()..];
                        let k: String = after
                            .chars()
                            .take_while(|c| !matches!(c, ' ' | '(' | ':'))
                            .collect();
                        if !k.is_empty() {
                            kind = k;
                            kind_is_sanitizer = true;
                        }
                        break;
                    }
                }
            }
            if kind.is_empty() {
                for (needle, tag) in [
                    ("runtime error: ", "ubsan"),
                    ("stack smashing detected", "stack-smashing"),
                    ("double free or corruption", "double-free"),
                    ("corrupted size vs. prev_size", "heap-corruption"),
                    ("malloc(): ", "heap-corruption"),
                    ("free(): ", "heap-corruption"),
                    ("munmap_chunk(): invalid pointer", "invalid-free"),
                    ("[signal: SIGSEGV]", "signal-SIGSEGV"),
                    ("[signal: SIGABRT]", "signal-SIGABRT"),
                    ("[signal: SIGBUS]", "signal-SIGBUS"),
                    ("[signal: SIGFPE]", "signal-SIGFPE"),
                    ("[signal: SIGILL]", "signal-SIGILL"),
                ] {
                    if line.contains(needle) {
                        kind = tag.to_string();
                        break;
                    }
                }
            }
        }
        // stack frames look like "    #0 0x... in func /src/file.c:10:5"
        let t = line.trim_start();
        if frames.len() < 6
            && t.starts_with('#')
            && let Some(p) = t.find(" in ")
        {
            let rest = &t[p + 4..];
            // function name: up to the source path or an address offset
            let func = rest.split(" /").next().unwrap_or(rest).trim();
            let func = func.split("+0x").next().unwrap_or(func).trim();
            if !func.is_empty() {
                frames.push(func.to_string());
            }
        }
    }

    if kind.is_empty() && frames.is_empty() {
        return String::new();
    }
    let mut sig = kind;
    if !frames.is_empty() {
        if !sig.is_empty() {
            sig.push('\n');
        }
        sig.push_str(&frames.join("\n"));
    }
    sig
}

/// The hash of the stack signature. Empty when there is no usable trace, so the
/// caller can fall back (for example to the input hash) rather than collapsing
/// every traceless crash onto one value.
pub fn stack_hash(output: &str) -> Option<String> {
    let sig = stack_signature(output);
    if sig.is_empty() {
        None
    } else {
        Some(hash_bytes(sig.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASAN_A: &str = "\
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0xdeadbeef
    #0 0x55a1 in process_record /src/parser.c:88:12
    #1 0x55b2 in handle /src/main.c:40
    #2 0x7f00 in __libc_start_main
";
    // same bug, different run: different addresses, same frames
    const ASAN_B: &str = "\
==9999==ERROR: AddressSanitizer: heap-use-after-free on address 0xcafef00d
    #0 0x12345 in process_record /src/parser.c:88:12
    #1 0x23456 in handle /src/main.c:40
    #2 0x99999 in __libc_start_main
";
    // a different bug
    const ASAN_C: &str = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1 in copy_bytes /src/buf.c:12
    #1 0x2 in handle /src/main.c:40
";

    #[test]
    fn same_bug_same_hash_regardless_of_address() {
        assert_eq!(stack_hash(ASAN_A), stack_hash(ASAN_B));
    }

    #[test]
    fn different_bug_different_hash() {
        assert_ne!(stack_hash(ASAN_A), stack_hash(ASAN_C));
    }

    #[test]
    fn signature_captures_kind_and_top_frame() {
        let sig = stack_signature(ASAN_A);
        assert!(sig.contains("heap-use-after-free"));
        assert!(sig.contains("process_record"));
        // the address is gone
        assert!(!sig.contains("0x55a1"));
    }

    #[test]
    fn no_trace_is_none() {
        assert_eq!(stack_hash(""), None);
        assert_eq!(stack_hash("just some unrelated output\n"), None);
    }

    #[test]
    fn libfuzzer_deadly_signal() {
        let out = "\
==5==ERROR: libFuzzer: deadly signal
    #0 0x1 in __sanitizer_print_stack_trace
    #1 0x2 in LLVMFuzzerTestOneInput /src/harness.c:7
";
        assert!(stack_hash(out).is_some());
        assert!(stack_signature(out).contains("LLVMFuzzerTestOneInput"));
    }

    #[test]
    fn glibc_stack_smashing_deduplicates() {
        let a = "*** stack smashing detected ***: terminated\n";
        let b = "*** stack smashing detected ***: terminated\n";
        assert_eq!(stack_hash(a), stack_hash(b));
        assert_eq!(stack_signature(a), "stack-smashing");
    }

    #[test]
    fn glibc_double_free() {
        let out = "free(): double free detected in tcache 2\n";
        assert!(stack_hash(out).is_some());
        assert!(stack_signature(out).starts_with("double-free")
            || stack_signature(out).starts_with("heap-corruption"));
    }

    #[test]
    fn glibc_heap_corruption() {
        let out = "corrupted size vs. prev_size while consolidating\n";
        assert_eq!(stack_signature(out), "heap-corruption");
    }

    #[test]
    fn glibc_malloc_error() {
        let out = "malloc(): unaligned tcache chunk detected\n";
        assert_eq!(stack_signature(out), "heap-corruption");
    }

    #[test]
    fn glibc_free_error() {
        let out = "free(): invalid pointer\n";
        assert_eq!(stack_signature(out), "heap-corruption");
    }

    #[test]
    fn glibc_munmap_invalid() {
        let out = "munmap_chunk(): invalid pointer\n";
        assert_eq!(stack_signature(out), "invalid-free");
    }

    #[test]
    fn signal_tag_deduplicates_traceless_crashes() {
        let a = "[signal: SIGSEGV]";
        let b = "[signal: SIGSEGV]";
        assert_eq!(stack_hash(a), stack_hash(b));
        assert_eq!(stack_signature(a), "signal-SIGSEGV");
    }

    #[test]
    fn different_signals_are_different_bugs() {
        let segv = "[signal: SIGSEGV]";
        let bus = "[signal: SIGBUS]";
        assert_ne!(stack_hash(segv), stack_hash(bus));
    }

    #[test]
    fn signal_after_output_still_uses_higher_priority_kind() {
        // if ASAN fires and the process also gets a signal, ASAN wins
        let out = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1 in copy_bytes /src/buf.c:12
[signal: SIGSEGV]";
        assert!(stack_signature(out).starts_with("heap-buffer-overflow"));
    }

    #[test]
    fn glibc_before_asan_prefers_asan() {
        // glibc prints "stack smashing detected" before ASAN's handler
        // fires; the signature should use ASAN's more specific class
        let out = "\
*** stack smashing detected ***: terminated
==1==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1
    #0 0x1 in handle_type_3 /src/vuln_parser.c:55
    #1 0x2 in main /src/vuln_parser.c:90
";
        let sig = stack_signature(out);
        assert!(sig.starts_with("stack-buffer-overflow"), "got: {sig}");
        assert!(sig.contains("handle_type_3"));
    }

    #[test]
    fn ubsan_runtime_error_recognized() {
        let out = "/src/math.c:42:5: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'\n";
        assert_eq!(stack_signature(out), "ubsan");
        assert!(stack_hash(out).is_some());
    }

    #[test]
    fn ubsan_with_frames_includes_kind() {
        let out = "\
/src/math.c:42:5: runtime error: signed integer overflow
    #0 0x4a2b3c in do_math /src/math.c:42:5
    #1 0x4a2e40 in main /src/main.c:100
";
        let sig = stack_signature(out);
        assert!(sig.starts_with("ubsan"), "got: {sig}");
        assert!(sig.contains("do_math"));
    }

    #[test]
    fn ubsan_overridden_by_asan() {
        // UBSan fires first, then ASAN catches the resulting corruption
        let out = "\
/src/math.c:42:5: runtime error: signed integer overflow
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1 in corrupt /src/buf.c:10
";
        let sig = stack_signature(out);
        assert!(sig.starts_with("heap-buffer-overflow"), "got: {sig}");
    }

    #[test]
    fn lsan_gets_real_kind() {
        let out = "\
==1234==ERROR: LeakSanitizer: detected memory leaks
Direct leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0x1 in malloc
    #1 0x2 in leaky_func /src/leak.c:10
";
        let sig = stack_signature(out);
        assert!(sig.starts_with("memory-leak"), "got: {sig}");
        assert!(sig.contains("leaky_func"));
    }

    #[test]
    fn stack_smashing_different_from_heap_overflow() {
        let smash = "*** stack smashing detected ***: terminated\n";
        let heap = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
    #0 0x1 in copy_bytes /src/buf.c:12
    #1 0x2 in handle /src/main.c:40
";
        assert_ne!(stack_hash(smash), stack_hash(heap));
    }
}
