use access_log_parser::{parse, CombinedLogEntry, LogEntry, LogType};
use chrono::{DateTime, FixedOffset};
use http::StatusCode;
use std::{fs::File, io::BufRead, net::IpAddr, str::FromStr};
use rs_filter::{Filterable, filter_for, EqFilter, OrdFilter, StringFilter};
use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

// desired syntax:
// log-filter <file> filter --user-agent contains "Chrome"
// log-filter <file> filter --ip eq "193.105.7.171"
// log-filter <file> filter --timestamp gt "2023-02-12T14:34:20+00:00" --ip eq "193.105.7.171"

#[derive(Parser, Debug)]
#[command(about = "Parse logs from a given file", name = "log-parser")]
struct Cli {
    file: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Filter(FilterArgs)
}

#[derive(Args, Debug)]
struct FilterArgs {
    #[arg(short, long, num_args = 1..=2)]
    status_code: Option<Vec<String>>,
    
    #[arg(short, long, num_args = 1..=2)]
    user_agent: Option<Vec<String>>,
    
    #[arg(short, long, num_args = 1..=2)]
    ip: Option<Vec<String>>,

    #[arg(short, long, num_args = 1..=2)]
    timestamp: Option<Vec<String>>,
}

fn parse_or_err<T: FromStr>(value: &str) -> Result<T, String> {
    value.parse().map_err(|_| format!("Invalid value for filter: {}", value))
}

fn parse_string_filter(args: Vec<String>) -> Result<StringFilter, String> {
    if args[0] == "none" {
        Ok(StringFilter::None)
    }
    else {
        match args[0].as_str() {
            "contains" => Ok(StringFilter::Contains(args[1].clone())),
            "eq" => Ok(StringFilter::Eq(args[1].clone())),
            "starts_with" => Ok(StringFilter::StartsWith(args[1].clone())),
            "ends_with" => Ok(StringFilter::EndsWith(args[1].clone())),
            _ => Err(format!("Invalid filter {}", args[0]))
        }
    }
}

fn parse_eq_filter<T: PartialEq + FromStr>(args: Vec<String>) -> Result<EqFilter<T>, String> {
    if args[0] == "none" {
        Ok(EqFilter::None)
    }
    else {
        match args[0].as_str() {
            "eq" => Ok(EqFilter::Eq(parse_or_err(args[1].as_str())?)),
            "neq" => Ok(EqFilter::Neq(parse_or_err(args[1].as_str())?)),
            _ => Err(format!("Invalid filter {}", args[0]))
        }
    }
}

fn parse_ord_filter<T: PartialOrd + FromStr>(args: Vec<String>) -> Result<OrdFilter<T>, String> {
    if args[0] == "none" {
        Ok(OrdFilter::None)
    }
    else {
        match args[0].as_str() {
            "eq" => Ok(OrdFilter::Eq(parse_or_err(args[1].as_str())?)),
            "neq" => Ok(OrdFilter::Neq(parse_or_err(args[1].as_str())?)),
            "gt" => Ok(OrdFilter::Gt(parse_or_err(args[1].as_str())?)),
            "lt" => Ok(OrdFilter::Lt(parse_or_err(args[1].as_str())?)),
            "gte" => Ok(OrdFilter::Gte(parse_or_err(args[1].as_str())?)),
            "lte" => Ok(OrdFilter::Lte(parse_or_err(args[1].as_str())?)),
            _ => Err(format!("Invalid filter {}", args[0]))
        }
    }
}

impl TryFrom<FilterArgs> for LogFilter {
    type Error = String;

    fn try_from(value: FilterArgs) -> Result<Self, Self::Error> {
        Ok(LogFilter {
            status_code: value.status_code.map_or(Ok(EqFilter::Any), parse_eq_filter)?,
            user_agent: value.user_agent.map_or(Ok(StringFilter::Any),parse_string_filter)?,
            ip: value.ip.map_or(Ok(EqFilter::Any), parse_eq_filter)?,
            timestamp: value.timestamp.map_or(Ok(OrdFilter::Any), parse_ord_filter)?,
        })
    }
}

#[filter_for(CombinedLogEntry<'a>)]
struct LogFilter {
    user_agent: StringFilter,
    status_code: EqFilter<StatusCode>,
    ip: EqFilter<IpAddr>,
    timestamp: OrdFilter<DateTime<FixedOffset>>,
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Filter(args) => {
            let filter: LogFilter = args.try_into()?;

            let file = File::open(cli.file).map_err(|e| e.to_string())?;
            let reader = std::io::BufReader::new(file);
            let lines = reader
                .lines()
                .filter(|l| l.as_ref().is_ok_and(|l| !l.is_empty()))
                .map(|l| l.unwrap());

            for line in lines {
                let entry = parse(LogType::CombinedLog, &line).map_err(|e| e.to_string())?;
                if let LogEntry::CombinedLog(entry) = entry {
                    if entry.is_match(&filter) {
                        println!("{}", line);
                    }
                }
            }
        }
    }

    Ok(())
}
