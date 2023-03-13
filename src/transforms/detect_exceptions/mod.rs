mod exception_detector;
use chrono::Utc;
pub use exception_detector::*;

use serde_with::serde_as;
use vector_config::configurable_component;

use crate::{
    config::{DataType, Input, Output, TransformConfig, TransformContext},
    event::{discriminant::Discriminant, Event},
    schema,
    transforms::{TaskTransform, Transform},
};
use async_stream::stream;
use futures::{stream, Stream, StreamExt};
use std::{collections::HashMap, pin::Pin, time::Duration};
use vector_core::config::LogNamespace;

/// ProgrammingLanguages
#[serde_as]
#[configurable_component]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum ProgrammingLanguages {
    /// Java
    Java,

    /// Python
    Python,

    /// Go
    Go,

    /// Ruby
    Ruby,
}

/// Configuration for the `detect_exceptions` transform.
#[serde_as]
#[configurable_component(transform("detect_exceptions"))]
#[derive(Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct DetectExceptionsConfig {
    /// Programming Languages for which to detect Exceptions
    ///
    /// Supported languages are
    ///   - Java
    ///   - Python
    ///   - Go
    ///   - Ruby
    pub languages: Vec<ProgrammingLanguages>,

    /// The maximum period of time to wait after the last event is received, in milliseconds, before
    /// a combined event should be considered complete.
    #[serde(default = "default_expire_after_ms")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub expire_after_ms: Duration,

    /// The interval to check for and flush any expired events, in milliseconds.
    #[serde(default = "default_flush_period_ms")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub flush_period_ms: Duration,

    /// An ordered list of fields by which to group events.
    ///
    /// Each group with matching values for the specified keys is reduced independently, allowing
    /// you to keep independent event streams separate. When no fields are specified, all events
    /// will be combined in a single group.
    ///
    /// For example, if `group_by = ["host", "region"]`, then all incoming events that have the same
    /// host and region will be grouped together before being reduced.
    #[serde(default)]
    #[configurable(metadata(
        docs::examples = "request_id",
        docs::examples = "user_id",
        docs::examples = "transaction_id",
    ))]
    pub group_by: Vec<String>,

    /// The interval of flushing the buffer for multiline exceptions.
    #[serde(default = "default_multiline_flush_interval_ms")]
    #[serde_as(as = "serde_with::DurationMilliSeconds<u64>")]
    pub multiline_flush_interval_ms: Duration,
}

impl Default for DetectExceptionsConfig {
    fn default() -> Self {
        Self {
            languages: vec![ProgrammingLanguages::Java],
            expire_after_ms: default_expire_after_ms(),
            flush_period_ms: default_flush_period_ms(),
            multiline_flush_interval_ms: default_multiline_flush_interval_ms(),
            group_by: vec![],
        }
    }
}

const fn default_expire_after_ms() -> Duration {
    Duration::from_millis(30000)
}

const fn default_flush_period_ms() -> Duration {
    Duration::from_millis(1000)
}

const fn default_multiline_flush_interval_ms() -> Duration {
    Duration::from_millis(1000)
}

impl_generate_config_from_default!(DetectExceptionsConfig);

#[async_trait::async_trait]
impl TransformConfig for DetectExceptionsConfig {
    async fn build(&self, _context: &TransformContext) -> crate::Result<Transform> {
        DetectExceptions::new(self).map(Transform::event_task)
    }

    fn input(&self) -> Input {
        Input::log()
    }

    fn outputs(&self, input: &schema::Definition, _: LogNamespace) -> Vec<Output> {
        let schema_definition = input.clone();
        vec![Output::default(DataType::Log).with_schema_definition(schema_definition)]
    }
}

pub struct DetectExceptions {
    accumulators: HashMap<Discriminant, TraceAccumulator>,
    expire_after: Duration,
    flush_period: Duration,
    multiline_flush_interval: Duration,
    group_by: Vec<String>,
}

impl DetectExceptions {
    pub fn new(config: &DetectExceptionsConfig) -> crate::Result<Self> {
        if config.languages.is_empty() {
            return Err("languages cannot be empty".into());
        }
        Ok(DetectExceptions {
            accumulators: HashMap::new(),
            group_by: config.group_by.clone().into_iter().collect(),
            expire_after: config.expire_after_ms,
            multiline_flush_interval: config.multiline_flush_interval_ms,
            flush_period: config.flush_period_ms,
        })
    }

    fn consume_one(&mut self, output: &mut Vec<Event>, e: Event) {
        let log_event = e.into_log();
        let discriminant = Discriminant::from_log_event(&log_event, &self.group_by);

        if !self.accumulators.contains_key(&discriminant) {
            self.accumulators.insert(
                discriminant.clone(),
                TraceAccumulator::new(self.multiline_flush_interval),
            );
        }
        let accumulator = self.accumulators.get_mut(&discriminant).unwrap();
        accumulator.push(&log_event, output);
    }

    fn flush_all_into(&mut self, output: &mut Vec<Event>) {
        for (k, v) in &mut self.accumulators {
            debug!("flushing {:?}, size: {}", k, v.accumulated_messages.len());
            v.flush(output);
        }
    }

    fn flush_stale_into(&mut self, output: &mut Vec<Event>) {
        let now = Utc::now();
        let mut for_removal: Vec<Discriminant> = vec![];
        for (k, v) in &mut self.accumulators {
            v.flush_stale_into(now, output);
            if v.accumulated_messages.len() == 0 {
                if now.timestamp_millis() - v.buffer_start_time.timestamp_millis()
                    > self.expire_after.as_millis().try_into().unwrap()
                {
                    for_removal.push(k.to_owned());
                }
            }
        }
        for d in for_removal {
            debug!("removing {:?}", d);
            self.accumulators.remove(&d);
        }
    }
}

impl TaskTransform<Event> for DetectExceptions {
    fn transform(
        self: Box<Self>,
        mut input_rx: Pin<Box<dyn Stream<Item = Event> + Send>>,
    ) -> Pin<Box<dyn Stream<Item = Event> + Send>>
    where
        Self: 'static,
    {
        let mut me = self;

        let poll_period = me.flush_period;

        let mut flush_stream = tokio::time::interval(poll_period);

        Box::pin(
            stream! {
              loop {
                let mut output = Vec::new();
                let done = tokio::select! {
                    _ = flush_stream.tick() => {
                      me.flush_stale_into(&mut output);
                      false
                    }
                    maybe_event = input_rx.next() => {
                      match maybe_event {
                        None => {
                          me.flush_all_into(&mut output);
                          true
                        }
                        Some(event) => {
                          me.consume_one(&mut output, event);
                          false
                        }
                      }
                    }
                };
                yield stream::iter(output.into_iter());
                if done { break }
              }
            }
            .flatten(),
        )
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn generate_config() {
        crate::test_util::test_generate_config::<DetectExceptionsConfig>();
    }
}

//
// TODO
// #1. pass config to TraceAccumulator
//     // done
// #2. expire stale events from TraceAccumulator
//     // done, tested
// #3. test group_by
//     // tested/working
// 4. Change JavaState to be independent of language, and have one Enum for all languages, Some
//    that a single start state can detect languagee based on the transition which matches
//  e.g.
//  enum LangState{
//    Start, // this is start state for all languages
//
//    Java_After_Exception,
//    Java
//
//    Go_After_Panic,
//    Go_Go_Routine,
//    Go_After_Signal,
//  }
// 5. Add/update unit test cases
// 6. Add config for max_bytes, max_lines
//
