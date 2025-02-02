use std::{fs::File, io, os::unix::prelude::{AsRawFd, FromRawFd}, sync::Arc, ffi::OsStr};

use libc::{c_int, c_void, size_t};

use crate::reply::ReplySender;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug, Clone)]
pub struct Channel(Arc<File>);

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let rc = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buffer.as_ptr() as *mut c_void,
                buffer.len() as size_t,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }

    pub fn duplicate(&self) -> io::Result<Channel> {
        use std::os::unix::ffi::OsStrExt;

        let master_fd = self.0.as_raw_fd();

        unsafe {
            let dev = std::ffi::CString::new("/dev/fuse").unwrap();
            let fd =
                libc::open(dev.as_bytes_with_nul().as_ptr() as *const libc::c_char,
                           libc::O_RDWR);
            if fd == -1 {
                log::error!("Failed to open fuse fd");
                return Err(io::Error::last_os_error());
            }
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);

            let ioc_clone = 0x_80_04_e5_00;
            let ctl_res = libc::ioctl(fd, ioc_clone, &master_fd);
            if ctl_res == -1 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }

            let file = Arc::new(File::from_raw_fd(fd));
            Ok(Channel(file))
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChannelSender(Arc<File>);

impl ReplySender for ChannelSender {
    fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = unsafe {
            libc::writev(
                self.0.as_raw_fd(),
                bufs.as_ptr() as *const libc::iovec,
                bufs.len() as c_int,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc as usize);
            Ok(())
        }
    }
}
