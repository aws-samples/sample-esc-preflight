mod cli;
mod depth;
mod deviation;
mod error;
mod extractor;
mod matcher;
mod model;
mod provider;
mod reader;
mod remediation;
mod report;
mod services;
#[cfg(test)]
mod test_inputs;
mod type_mapper;

fn main() {
    std::process::exit(cli::run());
}
