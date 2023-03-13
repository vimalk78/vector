use crate::{
    config::log_schema, event::LogEvent,
    internal_events::detect_exceptions::DetectExceptionsStaleEventFlushed,
    transforms::detect_exceptions::*,
};
use chrono::{DateTime, Utc};
use regex::Regex;
use std::borrow::Cow;

use std::collections::HashMap;
use std::usize;

#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub enum JavaState {
    StartException,
    AfterException,
    Java,
}

#[derive(Debug, Clone)]
pub struct Transition {
    regex: Regex,
    end_state: JavaState,
}

type JavaStateMachine = HashMap<JavaState, Vec<Transition>>;

fn make_java_state_machine() -> HashMap<JavaState, Vec<Transition>> {
    use JavaState::*;
    const JAVA_R1: &str = r"(?:Exception|Error|Throwable|V8 errors stack trace)[:\r\n]";
    const JAVA_R2: &str = r"^[\t ]*nested exception is:[\t ]*";
    const JAVA_R3: &str = r"^[\r\n]*$";
    const JAVA_R4: &str = r"^[\t ]+(?:eval )?at ";
    const JAVA_R5: &str = r"^[\t ]+--- End of inner exception stack trace ---$";
    const JAVA_R6: &str = r"^--- End of stack trace from previous (?x:
           )location where exception was thrown ---$";
    const JAVA_R7: &str = r"^[\t ]*(?:Caused by|Suppressed):";
    const JAVA_R8: &str = r"^[\t ]*... \d+ (?:more|common frames omitted)";
    HashMap::from([
        (
            StartException,
            vec![Transition {
                regex: Regex::new(JAVA_R1).unwrap(),
                end_state: AfterException,
            }],
        ),
        (
            AfterException,
            vec![
                Transition {
                    regex: Regex::new(JAVA_R2).unwrap(),
                    end_state: StartException,
                },
                Transition {
                    regex: Regex::new(JAVA_R3).unwrap(),
                    end_state: AfterException,
                },
                Transition {
                    regex: Regex::new(JAVA_R4).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R5).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R6).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R7).unwrap(),
                    end_state: AfterException,
                },
                Transition {
                    regex: Regex::new(JAVA_R8).unwrap(),
                    end_state: Java,
                },
            ],
        ),
        (
            Java,
            vec![
                Transition {
                    regex: Regex::new(JAVA_R4).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R5).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R6).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R8).unwrap(),
                    end_state: Java,
                },
                Transition {
                    regex: Regex::new(JAVA_R7).unwrap(),
                    end_state: AfterException,
                },
            ],
        ),
    ])
}

pub enum DetectionStatus {
    NoTrace,
    StartTrace,
    InsideTrace,
    EndTrace,
}

pub struct TraceAccumulator {
    max_bytes: usize,
    max_messages: usize,
    multiline_flush_interval: Duration,
    first_event: LogEvent,
    buffer_size: usize,
    detector: ExceptionDetector,
    pub buffer_start_time: DateTime<Utc>,
    pub accumulated_messages: Vec<String>,
}

impl TraceAccumulator {
    pub fn new(multiline_flush_interval: Duration) -> TraceAccumulator {
        TraceAccumulator {
            buffer_size: 0,
            max_bytes: 0,
            max_messages: 0,
            multiline_flush_interval,
            first_event: LogEvent::default(),
            buffer_start_time: Utc::now(),
            accumulated_messages: vec![],
            detector: ExceptionDetector {
                languages: vec![ProgrammingLanguages::Java],
                java_sm: make_java_state_machine(),
                current_state: JavaState::StartException,
            },
        }
    }

    pub fn push(&mut self, le: &LogEvent, output: &mut Vec<Event>) -> bool {
        let mut force_flush: bool = false;
        let mut detection_status = DetectionStatus::NoTrace;
        let message = le[log_schema().message_key()].as_str();
        let message_copy = message.clone();

        match message {
            None => self.detector.reset(),
            Some(s) => {
                if self.max_bytes > 0 && self.buffer_size + s.len() > self.max_bytes {
                    force_flush = true;
                }
                detection_status = self.detector.update(&s);
            }
        }

        self.update_buffer(detection_status, message_copy, le, output);

        if self.max_messages > 0 && self.accumulated_messages.len() == self.max_messages {
            force_flush = true;
        }
        force_flush
    }

    pub fn update_buffer(
        &mut self,
        detection_status: DetectionStatus,
        message: Option<Cow<str>>,
        le: &LogEvent,
        output: &mut Vec<Event>,
    ) {
        let trigger_emit = match detection_status {
            DetectionStatus::NoTrace => true,
            DetectionStatus::EndTrace => true,
            _ => false,
        };
        if self.accumulated_messages.is_empty() && trigger_emit {
            output.push(vector_core::event::Event::Log(le.to_owned()));
            return;
        }

        match detection_status {
            DetectionStatus::InsideTrace => self.add(le, message),
            DetectionStatus::EndTrace => {
                self.add(le, message);
                self.flush(output);
            }
            DetectionStatus::NoTrace => {
                self.flush(output);
                self.add(le, message);
                self.flush(output);
            }
            DetectionStatus::StartTrace => {
                self.flush(output);
                self.add(le, message);
            }
        }
    }

    pub fn add(&mut self, le: &LogEvent, message: Option<Cow<str>>) {
        if self.accumulated_messages.is_empty() {
            self.first_event = le.to_owned();
            self.buffer_start_time = Utc::now();
        }
        if let Some(line) = message {
            let line = line.to_string();
            let line_len = line.len();
            self.accumulated_messages.push(line);
            self.buffer_size += line_len;
        }
    }

    pub fn flush(&mut self, output: &mut Vec<Event>) {
        match self.accumulated_messages.len() {
            0 => return,
            1 => {
                output.push(vector_core::event::Event::Log(self.first_event.to_owned()));
            }
            _ => {
                self.first_event.insert(
                    log_schema().message_key(),
                    self.accumulated_messages.join("\n"),
                );
                output.push(vector_core::event::Event::Log(self.first_event.clone()));
            }
        }
        self.accumulated_messages = vec![];
        self.first_event = LogEvent::default();
        self.buffer_size = 0;
    }

    pub fn force_flush(&mut self, output: &mut Vec<Event>) {
        self.flush(output);
        self.detector.reset();
    }

    pub fn flush_stale_into(&mut self, now: DateTime<Utc>, output: &mut Vec<Event>) {
        if now.timestamp_millis() - self.buffer_start_time.timestamp_millis()
            > self
                .multiline_flush_interval
                .as_millis()
                .try_into()
                .unwrap()
        {
            emit!(DetectExceptionsStaleEventFlushed);
            self.force_flush(output);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExceptionDetectorConfig {}

pub struct ExceptionDetector {
    pub languages: Vec<ProgrammingLanguages>,
    pub java_sm: JavaStateMachine,
    pub current_state: JavaState,
}

impl ExceptionDetector {
    pub fn update(&mut self, line: &Cow<str>) -> DetectionStatus {
        let trace_seen_before = self.transition(line);
        if !trace_seen_before {
            self.transition(line);
        }
        let trace_seen_after = self.current_state != JavaState::StartException;
        match (trace_seen_before, trace_seen_after) {
            (true, true) => DetectionStatus::InsideTrace,
            (true, false) => DetectionStatus::EndTrace,
            (false, true) => DetectionStatus::StartTrace,
            (false, false) => DetectionStatus::NoTrace,
        }
    }

    pub fn transition(&mut self, message: &Cow<str>) -> bool {
        let transitions = self.java_sm.get(&(self.current_state)).unwrap();
        for transition in transitions {
            if transition.regex.is_match(message.as_ref()) {
                self.current_state = transition.end_state.clone();
                return true;
            }
        }
        self.current_state = JavaState::StartException;
        false
    }

    pub fn reset(&mut self) {
        self.current_state = JavaState::StartException;
    }
}

#[cfg(test)]
mod java_tests {

    use super::*;
    use crate::event::LogEvent;
    use crate::test_util::components::assert_transform_compliance;
    use crate::transforms::test::create_topology;
    use lookup::owned_value_path;
    //use serde_json::json;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use value::Kind;

    #[tokio::test]
    async fn test_exception_detector() {
        let detect_exceptions_config = toml::from_str::<DetectExceptionsConfig>(
            r#"
languages = [ "Java" ]

"#,
        )
        .unwrap();

        assert_transform_compliance(async move {
            let input_definition = schema::Definition::default_legacy_namespace().with_event_field(
                &owned_value_path!("counter"),
                Kind::integer(),
                None,
            );

            let _schema_definition = detect_exceptions_config
                .outputs(&input_definition, LogNamespace::Legacy)
                .first()
                .unwrap()
                .log_schema_definition
                .clone()
                .unwrap();

            let (tx, rx) = mpsc::channel(1);
            let (topology, mut out) =
                create_topology(ReceiverStream::new(rx), detect_exceptions_config).await;

            let java_simple_exception_trace = "
Jul 09, 2015 3:23:29 PM com.google.devtools.search.cloud.feeder.MakeLog: RuntimeException: Run from this message!
    at com.my.app.Object.do$a1(MakeLog.java:50)
    at java.lang.Thing.call(Thing.java:10)
    at com.my.app.Object.help(MakeLog.java:40)
    at sun.javax.API.method(API.java:100)
    at com.jetty.Framework.main(MakeLog.java:30)
                ";
            let mut counter = 1;
            let events = java_simple_exception_trace.trim().split("\n").map(|line| {
                let mut e = LogEvent::from(line);
                e.insert("counter",counter+=1);
                e
            });

            for event in events {
                tx.send(vector_core::event::Event::Log(event)).await.unwrap();
            }

            let next_msg = "Jul 09, 2015 3:23:39 PM new log message";
            tx.send(vector_core::event::Event::Log(LogEvent::from(next_msg.clone()))).await.unwrap();
            tx.send(vector_core::event::Event::Log(LogEvent::from(next_msg))).await.unwrap();


            println!("reached here 1");
            let output_1 = out.recv().await.unwrap().into_log();
            assert_eq!(output_1["message"], java_simple_exception_trace.trim().into());
            //assert_eq!(output_1["counter"], Value::from(1));
            //assert_eq!(output_1.metadata(), &metadata_1);
            //schema_definition.assert_valid_for_event(&output_1.into());

            println!("reached here 2");
            let output_2 = out.recv().await.unwrap().into_log();
            assert_eq!(output_2["message"], next_msg.into());
            //assert_eq!(output_2["counter"], Value::from(2));
            //assert_eq!(output_2.metadata(), &metadata_2);
            //schema_definition.assert_valid_for_event(&output_2.into());

            println!("reached here 3");
            drop(tx);
            println!("reached end of test case 1");
            topology.stop().await;
            println!("reached end of test case 2");
            //assert_eq!(out.recv().await, None);
        })
        .await;
    }

    fn run_state_machine(lines: Vec<&str>, debug: bool) -> String {
        let sm = make_java_state_machine();
        let mut state = JavaState::StartException;
        let mut combined_msg: Vec<&str> = vec![];
        for line in lines {
            println!("state: {:?}, line: {}", state, line);
            let mut found = false;
            let a = sm.get(&state).unwrap();
            for entry in a {
                if entry.regex.is_match(line) {
                    state = entry.end_state.clone();
                    combined_msg.push(line);
                    found = true;
                    break;
                } else {
                    if debug {
                        println!("failed regex: {}", entry.regex.to_string());
                    }
                }
            }
            if !found {
                println!("------ NOT MATCHED ---- line: {}", line);
                break;
            }
        }
        combined_msg.join("\n")
    }

    fn run_test(exception: &str) {
        let lines = exception.trim().split("\n").collect::<Vec<&str>>();
        let excep = run_state_machine(lines, true);
        assert_eq!(excep, exception.trim());
    }

    #[test]
    fn test_simple_exception() {
        run_test("
Jul 09, 2015 3:23:29 PM com.google.devtools.search.cloud.feeder.MakeLog: RuntimeException: Run from this message!
    at com.my.app.Object.do$a1(MakeLog.java:50)
    at java.lang.Thing.call(Thing.java:10)
    at com.my.app.Object.help(MakeLog.java:40)
    at sun.javax.API.method(API.java:100)
    at com.jetty.Framework.main(MakeLog.java:30)
            ");
    }

    #[test]
    fn test_complex_exception() {
        run_test(
            "
javax.servlet.ServletException: Something bad happened
    at com.example.myproject.OpenSessionInViewFilter.doFilter(OpenSessionInViewFilter.java:60)
    at org.mortbay.jetty.servlet.ServletHandler$CachedChain.doFilter(ServletHandler.java:1157)
    at com.example.myproject.ExceptionHandlerFilter.doFilter(ExceptionHandlerFilter.java:28)
    at org.mortbay.jetty.servlet.ServletHandler$CachedChain.doFilter(ServletHandler.java:1157)
    at com.example.myproject.OutputBufferFilter.doFilter(OutputBufferFilter.java:33)
    at org.mortbay.jetty.servlet.ServletHandler$CachedChain.doFilter(ServletHandler.java:1157)
    at org.mortbay.jetty.servlet.ServletHandler.handle(ServletHandler.java:388)
    at org.mortbay.jetty.security.SecurityHandler.handle(SecurityHandler.java:216)
    at org.mortbay.jetty.servlet.SessionHandler.handle(SessionHandler.java:182)
    at org.mortbay.jetty.handler.ContextHandler.handle(ContextHandler.java:765)
    at org.mortbay.jetty.webapp.WebAppContext.handle(WebAppContext.java:418)
    at org.mortbay.jetty.handler.HandlerWrapper.handle(HandlerWrapper.java:152)
    at org.mortbay.jetty.Server.handle(Server.java:326)
    at org.mortbay.jetty.HttpConnection.handleRequest(HttpConnection.java:542)
    at org.mortbay.jetty.HttpConnection$RequestHandler.content(HttpConnection.java:943)
    at org.mortbay.jetty.HttpParser.parseNext(HttpParser.java:756)
    at org.mortbay.jetty.HttpParser.parseAvailable(HttpParser.java:218)
    at org.mortbay.jetty.HttpConnection.handle(HttpConnection.java:404)
    at org.mortbay.jetty.bio.SocketConnector$Connection.run(SocketConnector.java:228)
    at org.mortbay.thread.QueuedThreadPool$PoolThread.run(QueuedThreadPool.java:582)
Caused by: com.example.myproject.MyProjectServletException
    at com.example.myproject.MyServlet.doPost(MyServlet.java:169)
    at javax.servlet.http.HttpServlet.service(HttpServlet.java:727)
    at javax.servlet.http.HttpServlet.service(HttpServlet.java:820)
    at org.mortbay.jetty.servlet.ServletHolder.handle(ServletHolder.java:511)
    at org.mortbay.jetty.servlet.ServletHandler$CachedChain.doFilter(ServletHandler.java:1166)
    at com.example.myproject.OpenSessionInViewFilter.doFilter(OpenSessionInViewFilter.java:30)
    ... 27 common frames omitted
            ",
        );
    }

    #[test]
    fn test_nested_exception() {
        run_test("
java.lang.RuntimeException: javax.mail.SendFailedException: Invalid Addresses;
  nested exception is:
com.sun.mail.smtp.SMTPAddressFailedException: 550 5.7.1 <[REDACTED_EMAIL_ADDRESS]>... Relaying denied

    at com.nethunt.crm.api.server.adminsync.AutomaticEmailFacade.sendWithSmtp(AutomaticEmailFacade.java:236)
    at com.nethunt.crm.api.server.adminsync.AutomaticEmailFacade.sendSingleEmail(AutomaticEmailFacade.java:285)
    at com.nethunt.crm.api.server.adminsync.AutomaticEmailFacade.lambda$sendSingleEmail$3(AutomaticEmailFacade.java:254)
    at java.util.Optional.ifPresent(Optional.java:159)
    at com.nethunt.crm.api.server.adminsync.AutomaticEmailFacade.sendSingleEmail(AutomaticEmailFacade.java:253)
    at com.nethunt.crm.api.server.adminsync.AutomaticEmailFacade.sendSingleEmail(AutomaticEmailFacade.java:249)
    at com.nethunt.crm.api.email.EmailSender.lambda$notifyPerson$0(EmailSender.java:80)
    at com.nethunt.crm.api.util.ManagedExecutor.lambda$execute$0(ManagedExecutor.java:36)
    at com.nethunt.crm.api.util.RequestContextActivator.lambda$withRequestContext$0(RequestContextActivator.java:36)
    at java.base/java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
    at java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
    at java.base/java.lang.Thread.run(Thread.java:748)
Caused by: javax.mail.SendFailedException: Invalid Addresses;
  nested exception is:
com.sun.mail.smtp.SMTPAddressFailedException: 550 5.7.1 <[REDACTED_EMAIL_ADDRESS]>... Relaying denied

    at com.sun.mail.smtp.SMTPTransport.rcptTo(SMTPTransport.java:2064)
    at com.sun.mail.smtp.SMTPTransport.sendMessage(SMTPTransport.java:1286)
    at com.nethunt.crm.api.server.adminsync.AutomaticEmailFacade.sendWithSmtp(AutomaticEmailFacade.java:229)
    ... 12 more
Caused by: com.sun.mail.smtp.SMTPAddressFailedException: 550 5.7.1 <[REDACTED_EMAIL_ADDRESS]>... Relaying denied
            ");
    }

    #[test]
    fn test_node_js_exception() {
        run_test(
            "
ReferenceError: myArray is not defined
  at next (/app/node_modules/express/lib/router/index.js:256:14)
  at /app/node_modules/express/lib/router/index.js:615:15
  at next (/app/node_modules/express/lib/router/index.js:271:10)
  at Function.process_params (/app/node_modules/express/lib/router/index.js:330:12)
  at /app/node_modules/express/lib/router/index.js:277:22
  at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
  at Route.dispatch (/app/node_modules/express/lib/router/route.js:112:3)
  at next (/app/node_modules/express/lib/router/route.js:131:13)
  at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)
  at /app/app.js:52:3
            ",
        );
    }

    /// This test fails
    #[ignore]
    #[test]
    fn test_client_js_client() {
        run_test(
            "
Error
    at bls (<anonymous>:3:9)
    at <anonymous>:6:4
    at a_function_name        
    at Object.InjectedScript._evaluateOn (http://<anonymous>/file.js?foo=bar:875:140)
    at Object.InjectedScript.evaluate (<anonymous>)
            ",
        );
    }

    /// This test fails
    #[ignore]
    #[test]
    fn test_v8_exception() {
        run_test(
            "
V8 errors stack trace   
  eval at Foo.a (eval at Bar.z (myscript.js:10:3))
  at new Contructor.Name (native)
  at new FunctionName (unknown location)
  at Type.functionName [as methodName] (file(copy).js?query='yes':12:9)
  at functionName [as methodName] (native)
  at Type.main(sample(copy).js:6:4)
            ",
        )
    }
}
