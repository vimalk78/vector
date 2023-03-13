use metrics::counter;
use vector_core::internal_event::InternalEvent;

#[derive(Debug)]
pub struct DetectExceptionsStaleEventFlushed;

impl InternalEvent for DetectExceptionsStaleEventFlushed {
    fn emit(self) {
        counter!("stale_exception_events_flushed_total", 1);
    }
}
