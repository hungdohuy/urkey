//! SSH agent messages from a (same-user) client: parsing and handling never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_agent::Agent;

fuzz_target!(|data: &[u8]| {
    let _ = ssh_agent::protocol::parse_request(data);
    let agent = Agent::new();
    let _ = agent.handle(data);
});
