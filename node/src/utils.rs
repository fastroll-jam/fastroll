use std::{future::Future, time::Instant};
use tokio::task::JoinHandle;

pub fn spawn_timed<F, T>(task_name: &'static str, fut: F) -> JoinHandle<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(async move {
        let start = Instant::now();
        let result = fut.await;
        tracing::trace!(%task_name, "task completed in {:?} μs", start.elapsed().as_micros());
        result
    })
}
