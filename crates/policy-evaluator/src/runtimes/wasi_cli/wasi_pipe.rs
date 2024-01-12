use std::{
    collections::VecDeque,
    io::{Read, Seek, Write},
};

// Code based on https://github.com/lapce/lapce/blob/f7d2f4ba863e3a00c9bcb0f3ac1896fd446e7d4c/lapce-proxy/src/plugin/wasi.rs#L45
/// A read/write pipe that can be used by Wasmtime's WasiCtx.
///
/// It can be used to implement the STDIN of a Wasi module. In this scenario,
/// it's safe to write to the `WasiPipe` instance multiple times. The Wasi guest
/// will find the data on its STDIN.
#[derive(Default)]
pub(crate) struct WasiPipe {
    buffer: VecDeque<u8>,
}

impl WasiPipe {
    pub fn new(data: &[u8]) -> Self {
        let mut buffer: VecDeque<u8> = VecDeque::new();
        buffer.extend(data);

        Self { buffer }
    }
}

impl Read for WasiPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let amt = std::cmp::min(buf.len(), self.buffer.len());
        for (i, byte) in self.buffer.drain(..amt).enumerate() {
            buf[i] = byte;
        }
        Ok(amt)
    }
}

impl Write for WasiPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Seek for WasiPipe {
    fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "can not seek in a pipe",
        ))
    }
}
