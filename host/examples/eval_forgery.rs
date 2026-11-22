//! Public-value forgery against a real eval proof: an operator edits the eval
//! report inside a valid proof (better grades, another seed, a delivered run
//! relabelled as missing). Every edit must make SP1 verification fail. Runs
//! withheld before proving are a different matter: they are reported as
//! missing by the proof itself (see `no_cherry_picking` in core/tests/eval.rs).
//!
//!   cargo run --release -p ph-host --example eval_forgery -- runs/eval-real/out

use std::path::PathBuf;

use ph_core::{EvalReport, GuestOutput};
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{include_elf, Elf, ProvingKey, SP1ProofWithPublicValues, SP1PublicValues};

const PH_ELF: Elf = include_elf!("ph-program");

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: eval_forgery <eval out dir>"));
    let proof = SP1ProofWithPublicValues::load(dir.join("proof.bin")).expect("proof.bin");
    let client = ProverClient::builder().light().build();
    let pk = client.setup(PH_ELF).unwrap();
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("untouched proof must verify");
    let GuestOutput::Eval(report) = GuestOutput::from_bytes(proof.public_values.as_slice()).unwrap() else {
        panic!("not an eval proof")
    };
    println!("untouched eval proof verifies ({} runs)", report.totals.runs);

    let mut forgeries: Vec<(&str, EvalReport)> = vec![];
    let mut r = report.clone();
    r.totals.exfil_attempted += 1;
    forgeries.push(("inflate attempts in the totals", r));
    let mut r = report.clone();
    if let Some(c) = r.runs[2].claim.as_mut() {
        let e = c.eval.as_mut().unwrap();
        e.task_completed = e.task_completed.map(|v| !v);
        e.utility = e.utility.map(|v| !v);
        e.attack_succeeded = Some(!e.attack_succeeded.unwrap_or(false));
    }
    forgeries.push(("flip one run's task grade", r));
    let mut r = report.clone();
    r.seed[0] ^= 1;
    forgeries.push(("claim another seed", r));
    let mut r = report.clone();
    r.runs[1].claim = None;
    r.totals.missing += 1;
    forgeries.push(("relabel a delivered run as missing", r));
    let mut r = report.clone();
    r.suite_name = "some-other-suite".into();
    forgeries.push(("rename the suite", r));

    let mut all = true;
    for (name, forged) in forgeries {
        let mut p = proof.clone();
        p.public_values = SP1PublicValues::from(&GuestOutput::Eval(forged).to_bytes());
        let res = client.verify(&p, pk.verifying_key(), None);
        let rejected = res.is_err();
        all &= rejected;
        println!("[{}] {name}: {res:?}", if rejected { "rejected as expected" } else { "ACCEPTED" });
    }
    if !all {
        eprintln!("SOME FORGERIES WERE ACCEPTED");
        std::process::exit(1);
    }
    println!("all forgeries rejected");
}
