mod args;
mod device;
mod pattern;
mod vanity_key;

use std::{fmt::Write, mem};

pub use args::*;
pub use device::DeviceList;
use indicatif::*;
use indicatif_log_bridge::LogWrapper;
pub use pattern::HashPattern;
pub use vanity_key::VanitySecretKey;

/// Do SHA-1 padding manually
/// A SHA-1 block is 512 bit, so the output Vec<u32> length is a multiple of 16
pub fn manually_prepare_sha1(hashdata: Vec<u8>) -> Vec<u32> {
    // Length after padding
    // Fill with 0x80 0x00 ... to 448 mod 512 bit, which is 56 mod 64 bytes
    // plus u64's 8 bytes, the length is a multiple of 64
    let padded_length = hashdata.len() + (64 - ((hashdata.len() + 8) % 64)) + 8;
    let mut result_u8 = Vec::with_capacity(padded_length);
    result_u8.extend_from_slice(&hashdata);
    result_u8.push(0x80);
    result_u8.resize(padded_length, 0);

    // convert Vec<u8> to Vec<u32>
    // https://stackoverflow.com/questions/49690459/converting-a-vecu32-to-vecu8-in-place-and-with-minimal-overhead
    let mut result_u32 = unsafe {
        let ptr = result_u8.as_mut_ptr() as *mut u32;
        let length = result_u8.len() / 4;
        let capacity = result_u8.capacity() / 4;
        mem::forget(result_u8);
        Vec::from_raw_parts(ptr, length, capacity)
    };

    // assert_eq!(result_u32.len() % 16, 0);
    // SHA-1 uses big-endian words and length
    for pos in &mut result_u32 {
        *pos = pos.to_be();
    }

    let bit_length = hashdata.len() * 8;
    result_u32[padded_length / 4 - 1] = (bit_length) as u32;
    result_u32[padded_length / 4 - 2] = (bit_length >> 32) as u32;
    result_u32
}

pub fn init_logger() -> MultiProgress {
    let logger = env_logger::Builder::from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    )
    .format_indent(None)
    .build();

    let level = logger.filter();
    let multi = MultiProgress::new();

    LogWrapper::new(multi.clone(), logger).try_init().unwrap();
    log::set_max_level(level);

    multi
}

pub fn init_progress_bar(estimate: Option<f64>, unit: &'static str) -> ProgressBar {
    let bar = match estimate.filter(|value| value.is_finite() && *value < u64::MAX as f64) {
        Some(estimate) => ProgressBar::new(estimate as u64),
        None => ProgressBar::new_spinner(),
    };

    bar.set_style(
        ProgressStyle::default_spinner()
            .template(if bar.length().is_some() {
                "[{elapsed_precise}] {bar:50.cyan/blue} {progress} {rate} > {eta_precise}"
            } else {
                "[{elapsed_precise}] {spinner} {progress} {rate}"
            })
            .unwrap()
            .progress_chars("##-")
            .with_key(
                "progress",
                move |state: &ProgressState, w: &mut dyn Write| {
                    write!(w, "{}", format_number(state.pos() as f64)).unwrap();
                    if let Some(estimate) = estimate {
                        write!(w, "/{}", format_number(estimate)).unwrap();
                    }
                },
            )
            .with_key("rate", move |state: &ProgressState, w: &mut dyn Write| {
                write!(
                    w,
                    "{} {unit}",
                    format_number(
                        (state.pos() as f64) / state.elapsed().as_secs_f64().max(f64::EPSILON)
                    ),
                )
                .unwrap()
            }),
    );

    bar
}

pub fn format_number(v: impl Into<f64>) -> String {
    match Into::<f64>::into(v) {
        v if v >= 1e15f64 => format!("{v:.02e}"),
        v if v >= 1e12f64 => {
            format!("{:.02}T", v / 1e12f64)
        }
        v if v >= 1e9f64 => {
            format!("{:.02}B", v / 1e9f64)
        }
        v if v >= 1e6f64 => {
            format!("{:.02}M", v / 1e6f64)
        }
        v if v >= 1e3f64 => {
            format!("{:.02}K", v / 1e3f64)
        }
        v => {
            format!("{v:.02}")
        }
    }
}
