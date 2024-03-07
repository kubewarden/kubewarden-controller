use futures::{
    future::BoxFuture,
    task::{Context, Poll},
    Future, FutureExt,
};
use lazy_static::lazy_static;
use pprof::protos::Message;
use regex::Regex;
use std::{pin::Pin, sync::Mutex};
use thiserror::Error;

lazy_static! {
    // If it's some it means there are already a CPU profiling.
    static ref CPU_PROFILE_ACTIVE: Mutex<Option<()>> = Mutex::new(None);

    // To normalize thread names.
    static ref THREAD_NAME_RE: Regex =
        Regex::new(r"^(?P<thread_name>[a-z-_ :]+?)(-?\d)*$").unwrap();
    static ref THREAD_NAME_REPLACE_SEPERATOR_RE: Regex = Regex::new(r"[_ ]").unwrap();
}

#[derive(Debug, Error)]
pub enum ReportGenerationError {
    #[error("CPU profile already running")]
    CPUAlreadyProfiling,

    #[error("pprof error: {0}")]
    PprofError(#[from] pprof::Error),

    #[error("cannot encode report to pprof format: {0}")]
    EncodeError(String),
}

/// Default frequency of sampling. 99Hz to avoid coincide with special periods
pub fn default_profiling_frequency() -> i32 {
    99
}

/// Default profiling interval time - 30 seconds
pub fn default_profiling_interval() -> u64 {
    30
}

/// Trigger one cpu profile.
pub async fn start_one_cpu_profile<F>(
    end: F,
    frequency: i32,
) -> Result<Vec<u8>, ReportGenerationError>
where
    F: Future<Output = Result<(), ReportGenerationError>> + Send + 'static,
{
    if CPU_PROFILE_ACTIVE.lock().unwrap().is_some() {
        return Err(ReportGenerationError::CPUAlreadyProfiling);
    }

    let on_start = || {
        let mut activate = CPU_PROFILE_ACTIVE.lock().unwrap();
        assert!(activate.is_none());
        *activate = Some(());
        let guard = pprof::ProfilerGuardBuilder::default()
            .frequency(frequency)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()?;
        Ok(guard)
    };

    let on_end = move |guard: pprof::ProfilerGuard<'static>| {
        let report = guard
            .report()
            .frames_post_processor(move |frames| {
                let name = extract_thread_name(&frames.thread_name);
                frames.thread_name = name;
            })
            .build()?;
        let mut body = Vec::new();
        let profile = report.pprof()?;

        profile
            .encode(&mut body)
            .map_err(|e| ReportGenerationError::EncodeError(e.to_string()))?;

        drop(guard);
        *CPU_PROFILE_ACTIVE.lock().unwrap() = None;

        Ok(body)
    };

    ProfileRunner::new(on_start, on_end, end.boxed())?.await
}

fn extract_thread_name(thread_name: &str) -> String {
    THREAD_NAME_RE
        .captures(thread_name)
        .and_then(|cap| {
            cap.name("thread_name").map(|thread_name| {
                THREAD_NAME_REPLACE_SEPERATOR_RE
                    .replace_all(thread_name.as_str(), "-")
                    .into_owned()
            })
        })
        .unwrap_or_else(|| thread_name.to_owned())
}

type OnEndFn<I, T> = Box<dyn FnOnce(I) -> Result<T, ReportGenerationError> + Send + 'static>;

struct ProfileRunner<I, T> {
    item: Option<I>,
    on_end: Option<OnEndFn<I, T>>,
    end: BoxFuture<'static, Result<(), ReportGenerationError>>,
}

impl<I, T> Unpin for ProfileRunner<I, T> {}

impl<I, T> ProfileRunner<I, T> {
    fn new<F1, F2>(
        on_start: F1,
        on_end: F2,
        end: BoxFuture<'static, Result<(), ReportGenerationError>>,
    ) -> Result<Self, ReportGenerationError>
    where
        F1: FnOnce() -> Result<I, ReportGenerationError>,
        F2: FnOnce(I) -> Result<T, ReportGenerationError> + Send + 'static,
    {
        let item = on_start()?;
        Ok(ProfileRunner {
            item: Some(item),
            on_end: Some(Box::new(on_end) as OnEndFn<I, T>),
            end,
        })
    }
}

impl<I, T> Future for ProfileRunner<I, T> {
    type Output = Result<T, ReportGenerationError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.end.as_mut().poll(cx) {
            Poll::Ready(res) => {
                let item = self.item.take().unwrap();
                let on_end = self.on_end.take().unwrap();
                let r = match (res, on_end(item)) {
                    (Ok(_), r) => r,
                    (Err(errmsg), _) => Err(errmsg),
                };
                Poll::Ready(r)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
