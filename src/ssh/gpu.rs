use anyhow::{bail, Context as _, Result};
use ocl::{
    core::DeviceInfo, enums::DeviceInfoResult, flags, Buffer, Context, Device, Kernel, Platform,
    Program, Queue,
};

const KEYS_PER_ITEM: usize = 32;
const TABLE_WORK_ITEMS: usize = 16 * 32769 + 1;

pub(super) const RESULTS_CAP: usize = 4096;

pub(super) struct Gpu {
    kernel: Kernel,
    _seed_buf: Buffer<u8>,
    _masks_buf: Buffer<u64>,
    results_buf: Buffer<u64>,
    count_buf: Buffer<u32>,
    _table_buf: Buffer<u64>,
    pub(super) batch: usize,
}

impl Gpu {
    pub(super) fn new(
        device: Device,
        seed: &[u8; 32],
        masks: &[u64; 16],
        plen: u32,
        mode: u32,
        batch: usize,
    ) -> Result<Self> {
        let batch = (batch / KEYS_PER_ITEM * KEYS_PER_ITEM).max(KEYS_PER_ITEM);
        if batch > u32::MAX as usize {
            bail!("batch exceeds the 32-bit result counter capacity");
        }
        if plen as usize > masks.len() {
            bail!(
                "pattern length {plen} exceeds the {} mask slots",
                masks.len()
            );
        }
        let platform = match device.info(DeviceInfo::Platform)? {
            DeviceInfoResult::Platform(id) => Platform::new(id),
            _ => bail!("device platform info unavailable"),
        };
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()
            .context("OpenCL context")?;
        let queue = Queue::new(&context, device, None).context("OpenCL command queue")?;
        let program = Program::builder()
            .src(include_str!("vanity.cl"))
            .build(&context)
            .context("building OpenCL program")?;

        let seed_buf = Buffer::<u8>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR)
            .copy_host_slice(&seed[..])
            .len(seed.len())
            .build()
            .context("seed buffer")?;
        let masks_buf = Buffer::<u64>::builder()
            .queue(queue.clone())
            .flags(flags::MEM_READ_ONLY | flags::MEM_COPY_HOST_PTR)
            .copy_host_slice(&masks[..])
            .len(masks.len())
            .build()
            .context("masks buffer")?;
        let results_buf = Buffer::<u64>::builder()
            .queue(queue.clone())
            .len(RESULTS_CAP)
            .build()
            .context("results buffer")?;
        let count_buf = Buffer::<u32>::builder()
            .queue(queue.clone())
            .len(1)
            .build()
            .context("count buffer")?;
        let table_buf = Buffer::<u64>::builder()
            .queue(queue.clone())
            .len(TABLE_WORK_ITEMS * 15)
            .build()
            .context("table buffer")?;

        let table_kernel = Kernel::builder()
            .program(&program)
            .name("gen_table")
            .queue(queue.clone())
            .global_work_size(TABLE_WORK_ITEMS)
            .arg(&table_buf)
            .build()
            .context("gen_table kernel")?;
        unsafe { table_kernel.enq() }.context("enqueue gen_table")?;
        queue.finish().context("gen_table finish")?;

        let kernel = Kernel::builder()
            .program(&program)
            .name("vanity")
            .queue(queue.clone())
            .global_work_size(batch / KEYS_PER_ITEM)
            .arg(&seed_buf)
            .arg(0u64)
            .arg(&masks_buf)
            .arg(plen as i32)
            .arg(mode as i32)
            .arg(&results_buf)
            .arg(&count_buf)
            .arg(&table_buf)
            .build()
            .context("vanity kernel")?;

        Ok(Gpu {
            kernel,
            _seed_buf: seed_buf,
            _masks_buf: masks_buf,
            results_buf,
            count_buf,
            _table_buf: table_buf,
            batch,
        })
    }

    pub(super) fn scan(&mut self, start_offset: u64) -> Result<(Vec<u64>, bool)> {
        self.kernel
            .set_arg(1, start_offset)
            .context("set start offset")?;
        let zero = [0u32; 1];
        self.count_buf
            .write(&zero[..])
            .enq()
            .context("reset result count")?;
        unsafe { self.kernel.enq() }.context("enqueue vanity kernel")?;
        let mut count = [0u32; 1];
        self.count_buf
            .read(&mut count[..])
            .enq()
            .context("read result count")?;
        let n = (count[0] as usize).min(RESULTS_CAP);
        let mut results = vec![0u64; n];
        if n > 0 {
            self.results_buf
                .read(&mut results)
                .enq()
                .context("read results")?;
        }
        Ok((results, count[0] as usize > RESULTS_CAP))
    }
}
