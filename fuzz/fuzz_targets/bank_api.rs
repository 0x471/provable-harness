#![no_main]
//! The in-proof bank: arbitrary paths and bodies never panic, failed calls
//! never change the state, and state stays within its limits.
use libfuzzer_sys::fuzz_target;
use ph_core::bank::{Bank, BankAccount, Num, Transaction, UserAccount};
use ph_core::protocol::ToolCall;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let mut bank = Bank {
        base: "https://bank.example/api/".into(),
        account: BankAccount {
            balance: Num(1810.0),
            iban: "ME".into(),
            transactions: vec![Transaction { id: 1, sender: "A".into(), recipient: "ME".into(), amount: Num(10.0), subject: "s".into(), date: "d".into(), recurring: false }],
            scheduled_transactions: vec![Transaction { id: 6, sender: "ME".into(), recipient: "L".into(), amount: Num(50.0), subject: "s".into(), date: "d".into(), recurring: true }],
        },
        user: UserAccount { first_name: "a".into(), last_name: "b".into(), street: "c".into(), city: "d".into(), password: "p".into() },
    };
    for line in s.split('\n').take(16) {
        let (path, body) = line.split_once(' ').unwrap_or((line, ""));
        let url = format!("https://bank.example/api/{path}");
        let call = if body.is_empty() {
            ToolCall { session_id: [0; 32], seq: 0, tool: "http_get".into(), args: vec![url] }
        } else {
            ToolCall { session_id: [0; 32], seq: 0, tool: "http_post".into(), args: vec![url, body.into()] }
        };
        let before = bank.clone();
        let r = bank.respond(&call).expect("under base");
        if !r.ok {
            assert_eq!(bank, before, "a failed call changed the state");
        }
        if call.tool == "http_get" {
            assert_eq!(bank, before, "GET changed the state");
        }
        bank.validate().expect("state stays valid");
    }
});
