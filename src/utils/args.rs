use clap::{Parser, ValueEnum};
use std::sync::LazyLock;

pub static ARGS: LazyLock<Args> = LazyLock::new(Args::parse);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long, help = "Generate vanity SSH Ed25519 keys instead of OpenPGP keys", conflicts_with_all = ["cipher_suite", "user_id", "filter", "thread", "iteration", "future_timestamp", "start_timestamp", "max_time_range"])]
    pub ssh: bool,

    #[arg(
        long,
        requires = "ssh",
        help = "SSH candidates per OpenCL launch, rounded down to a multiple of 32 (minimum: 32; default: 1048576 GPU, 65536 CPU)"
    )]
    pub batch: Option<usize>,

    /// Cipher suite of the vanity key
    /// ed25519, ecdsa-****, rsa**** => Primary key
    /// cv25519,  ecdh-****          => Subkey
    /// Use gpg CLI for further editing of the key.
    #[arg(short, long, default_value_t, value_enum, verbatim_doc_comment)]
    pub cipher_suite: CipherSuite,

    /// OpenPGP compatible user ID
    #[arg(short, long, default_value_t = String::from("Dummy <dummy@example.com>"))]
    pub user_id: String,

    /// A pattern less than 40 chars for matching fingerprints
    /// > Format:
    /// * 0-9A-F are fixed, G-Z are wildcards
    /// * Other chars will be ignored
    /// * Case insensitive
    /// > Example:
    /// * 11XXXX** may output a fingerprint ends with 11222234 or 11AAAABF
    /// * 11XXYYZZ may output a fingerprint ends with 11223344 or 11AABBCC
    #[arg(
        short,
        long,
        verbatim_doc_comment,
        help = "GPG fingerprint pattern; with --ssh, a case-sensitive literal suffix of the full SSH public key line (e.g. love matches keys ending in love)",
        long_help = "GPG: up to 40 characters, case-insensitive and right-aligned. 0-9A-F are fixed; repeated G-Z letters require equal digits. Example: 11XXYYZZ.\nSSH (--ssh): by default, a case-sensitive literal suffix of the full ssh-ed25519 public key line, not its SHA256 fingerprint: -p love matches lines ending in love, no escaping or quotes needed. With --regex, the original upstream regex applies instead on the full public key line: Base64 literals, character classes anywhere, and ^/$ anchors, but repetition, dot, negated classes and multi-character alternatives are unsupported. Examples: love; --regex -p 'love$'; --regex -p '[pP][cC][aA][rR]'."
    )]
    pub pattern: Option<String>,

    #[arg(
        long,
        requires = "ssh",
        default_value_t = false,
        help = "With --ssh, match --pattern as the original upstream regex on the full SSH public key line instead of a literal suffix"
    )]
    pub regex: bool,

    /// OpenCL kernel function for uint h[5] for matching fingerprints
    /// Ignore the pattern and no estimate is given if this has been set
    /// > Example:
    /// * (h[4] & 0xFFFF)     == 0x1234     outputs a fingerprint ends with 1234
    /// * (h[0] & 0xFFFF0000) == 0xABCD0000 outputs a fingerprint starts with ABCD
    #[arg(short, long, verbatim_doc_comment)]
    pub filter: Option<String>,

    /// The dir where the vanity keys are saved
    #[arg(short, long)]
    pub output: Option<String>,

    /// Device ID to use
    #[arg(short, long)]
    pub device: Option<usize>,

    /// Adjust it to maximum your device's usage
    #[arg(short, long)]
    pub thread: Option<usize>,

    /// Adjust it to maximum your device's usage
    #[arg(short, long, default_value_t = 1 << 9)]
    pub iteration: usize,

    /// Exit after a specified time in seconds
    #[arg(long)]
    pub timeout: Option<f64>,

    /// Exit after getting a vanity key
    #[arg(long, default_value_t = false)]
    pub oneshot: bool,

    /// Don't print progress
    #[arg(long, default_value_t = false)]
    pub no_progress: bool,

    /// Don't print armored secret key
    #[arg(long, default_value_t = false)]
    pub no_secret_key_logging: bool,

    /// Show available OpenCL devices then exit
    #[arg(long, default_value_t = false)]
    pub list_device: bool,

    /// Generate keys with future timestamps instead of past timestamps
    /// When true: search from start_timestamp forward in time (start_timestamp + 0 to max_time_range)
    /// When false: search from start_timestamp backward in time (start_timestamp - max_time_range to start_timestamp - 0)
    #[arg(long, default_value_t = false, verbatim_doc_comment)]
    pub future_timestamp: bool,

    /// Custom timestamp to start searching from (Unix timestamp)
    /// This is the base time point from which the search begins
    /// If not specified, uses current time as the starting point
    /// Example: 1640995200 (Jan 1, 2022 00:00:00 UTC)
    #[arg(long, verbatim_doc_comment)]
    pub start_timestamp: Option<i64>,

    /// Maximum time range to search in seconds
    /// future_timestamp =  true: search from start_timestamp to (start_timestamp + max_time_range)
    /// future_timestamp = false: search from (start_timestamp - max_time_range) to start_timestamp
    #[arg(long, verbatim_doc_comment)]
    pub max_time_range: Option<u32>,
}

/// Cipher Suites
#[derive(ValueEnum, Default, Clone, Copy, Debug)]
#[clap(rename_all = "kebab_case")]
pub enum CipherSuite {
    #[default]
    Ed25519,
    Cv25519,
    RSA2048,
    RSA3072,
    RSA4096,
    EcdhP256,
    EcdhP384,
    EcdhP521,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}
