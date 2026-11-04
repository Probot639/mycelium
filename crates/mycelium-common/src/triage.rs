use crate::corpus::hash_bytes;

/// Reduce sanitizer or libFuzzer output to a stable per-bug signature: the error
/// class plus the top stack frames, with volatile addresses and offsets dropped.
/// Two crashing inputs that hit the same bug produce the same signature, so the
/// coordinator can group them.
pub fn stack_signature(output: &str) -> String {
    let mut kind = String::new();
    let mut frames: Vec<String> = Vec::new();

    for line in output.lines() {
        if kind.is_empty() {
            for marker in ["Sanitizer: ", "libFuzzer: "] {
                if let Some(i) = line.find(marker) {
                    let after = &line[i + marker.len()..];
                    let k: String = after
                        .chars()
                        .take_while(|c| !matches!(c, ' ' | '(' | ':'))
                        .collect();
                    if !k.is_empty() {
                        kind = k;
                    }
                    break;
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
}
