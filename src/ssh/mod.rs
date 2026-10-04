mod filter;
mod gpu;
mod openssh;

use anyhow::{bail, Context};
use ed25519_dalek::SigningKey;
use indicatif::{MultiProgress, ProgressDrawTarget};
use log::{info, warn};
use ocl::{core::DeviceInfo, enums::DeviceInfoResult, flags, Device};
use rand::{rngs::OsRng, RngCore};
use std::{fs::OpenOptions, io::Write, path::Path, time::Instant};

use crate::utils::{format_number, init_progress_bar, Args};

pub(super) fn run(args: &Args, device: Device, bars: &MultiProgress) -> anyhow::Result<()> {
    let pattern = args
        .pattern
        .as_deref()
        .context("No SSH pattern given; use --ssh -p love")?;
    let expression = if args.regex {
        pattern.to_owned()
    } else {
        format!("{}$", regex::escape(pattern))
    };
    let filter = filter::compile(&expression)?;
    if args
        .timeout
        .is_some_and(|timeout| !timeout.is_finite() || timeout <= 0.0)
    {
        bail!("Timeout must be a finite positive number of seconds");
    };
    if let Some(output) = &args.output {
        std::fs::create_dir_all(output)?;
    } else if args.no_secret_key_logging {
        bail!("SSH keys need --output when --no-secret-key-logging is set");
    } else {
        warn!("No output directory given; SSH private keys will only be printed");
    }

    let mut rng = OsRng;
    let mut base_seed = [0u8; 32];
    rng.try_fill_bytes(&mut base_seed)
        .context("Could not obtain a random SSH seed")?;
    info!("Preparing SSH Ed25519 OpenCL backend");
    let mut gpu = gpu::Gpu::new(
        device,
        &base_seed,
        &filter.masks,
        filter.len,
        filter.mode as u32,
        args.batch.unwrap_or(
            if matches!(device.info(DeviceInfo::Type)?,
        DeviceInfoResult::Type(kind) if kind.contains(flags::DEVICE_TYPE_CPU))
            {
                1 << 16
            } else {
                1 << 20
            },
        ),
    )?;
    info!("SSH batch: {}", gpu.batch);
    let bar = bars.add(init_progress_bar(
        (!args.regex && pattern.len() <= 42).then(|| 64_f64.powi(pattern.len() as i32)),
        "key/s",
    ));
    if args.no_progress {
        bar.set_draw_target(ProgressDrawTarget::hidden());
    }
    info!("Looking for SSH public keys matching {pattern:?}");
    let mut offset = 0u64;
    let mut searched = 0u64;
    let mut start = Instant::now();

    let regex = regex::Regex::new(&expression)?;

    loop {
        if args
            .timeout
            .is_some_and(|timeout| start.elapsed().as_secs_f64() >= timeout)
        {
            info!("Timeout!");
            break;
        }
        let (candidates, overflow) = gpu.scan(offset)?;
        searched = searched.saturating_add(gpu.batch as u64);
        bar.inc(gpu.batch as u64);
        if overflow {
            warn!("More than {} SSH filter hits in one batch; some candidates were skipped. Reduce --batch or use a more selective pattern", gpu::RESULTS_CAP);
        }
        for candidate in candidates {
            let mut seed = base_seed;
            seed[24..].copy_from_slice(
                &u64::from_le_bytes(base_seed[24..].try_into()?)
                    .wrapping_add(candidate)
                    .to_le_bytes(),
            );
            let pubkey = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            let line = openssh::authorized_line(&pubkey);
            if !regex.is_match(&line) {
                continue;
            }
            let mut private = [0u8; 64];
            private[..32].copy_from_slice(&seed);
            private[32..].copy_from_slice(&pubkey);
            let mut checkint = [0u8; 4];
            rng.try_fill_bytes(&mut checkint)
                .context("Could not obtain an SSH check integer")?;
            let pem = openssh::private_pem(&private, &pubkey, u32::from_le_bytes(checkint));
            if let Some(output) = &args.output {
                let path = Path::new(output).join(format!("id_ed25519_{}", hex::encode(pubkey)));
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                options.open(&path)?.write_all(pem.as_bytes())?;
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path.with_extension("pub"))?
                    .write_all(format!("{line}\n").as_bytes())?;
                info!("Saved SSH key: {}", path.display());
            }
            info!("Public key:\n{line}");
            if !args.no_secret_key_logging {
                info!("Private key:\n{pem}");
            }
            let elapsed = start.elapsed().as_secs_f64();
            info!(
                "Generated: {} Time: {elapsed:.02}s Speed: {} key/s",
                format_number(searched as f64),
                format_number(searched as f64 / elapsed)
            );
            if args.oneshot {
                bar.finish();
                bars.clear()?;
                return Ok(());
            }
            searched = 0;
            start = Instant::now();
            bar.reset();
            break;
        }
        offset = offset
            .checked_add(gpu.batch as u64)
            .context("SSH seed counter exhausted; restart with a fresh seed")?;
    }
    bar.finish();
    bars.clear()?;
    Ok(())
}
