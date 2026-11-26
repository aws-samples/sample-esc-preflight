mod account;
mod cli;
mod compare;
mod depth;
mod deviation;
mod error;
mod extractor;
mod matcher;
mod mitigations;
mod model;
mod output;
mod plan;
mod provider;
mod reader;
mod remediation;
mod report;
mod rules;
mod sam;
mod services;
mod summary;
#[cfg(test)]
mod test_inputs;
mod tui;
mod type_mapper;

fn main() {
    std::process::exit(cli::run());
}
