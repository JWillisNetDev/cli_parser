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
    #[arg(short, long)]
    status_code: Option<String>,
    
    #[arg(short, long)]
    user_agent: Option<String>,
    
    #[arg(short, long)]
    ip: Option<String>,

    #[arg(short, long)]
    timestamp: Option<String>,
}

fn explode_args(value: &str) -> Result<Vec<&str>, String> {
    let args: Vec<&str> = value.splitn(2, ' ').collect();

    if args.len() != 2 {
        Err(format!("Invalid filter {}", value))
    }
    else {
        Ok(args)
    }
}

fn parse_or_err<T: FromStr>(value: &str) -> Result<T, String> {
    value.parse().map_err(|_| format!("Invalid value for filter: {}", value))
}

fn parse_string_filter(value: impl AsRef<str>) -> Result<StringFilter, String> {
    let value = value.as_ref();
    if value == "none" {
        Ok(StringFilter::None)
    }
    else {
        let args = explode_args(value)?;
        match args[0] {
            "contains" => Ok(StringFilter::Contains(args[1].to_string())),
            "eq" => Ok(StringFilter::Eq(args[1].to_string())),
            "starts_with" => Ok(StringFilter::StartsWith(args[1].to_string())),
            "ends_with" => Ok(StringFilter::EndsWith(args[1].to_string())),
            _ => Err(format!("Invalid filter {}", value))
        }
    }
}

fn parse_eq_filter<T: PartialEq + FromStr>(value: impl AsRef<str>) -> Result<EqFilter<T>, String> {
    let value = value.as_ref();
    if value == "none" {
        Ok(EqFilter::None)
    }
    else {
        let args = explode_args(value)?;
        match args[0] {
            "eq" => Ok(EqFilter::Eq(parse_or_err(args[1])?)),
            "neq" => Ok(EqFilter::Neq(parse_or_err(args[1])?)),
            _ => Err(format!("Invalid filter {}", value))
        }
    }
}

fn parse_ord_filter<T: PartialOrd + FromStr>(value: impl AsRef<str>) -> Result<OrdFilter<T>, String> {
    let value = value.as_ref();
    if value == "none" {
        Ok(OrdFilter::None)
    }
    else {
        let args = explode_args(value)?;
        match args[0] {
            "eq" => Ok(OrdFilter::Eq(parse_or_err(args[1])?)),
            "neq" => Ok(OrdFilter::Neq(parse_or_err(args[1])?)),
            "gt" => Ok(OrdFilter::Gt(parse_or_err(args[1])?)),
            "lt" => Ok(OrdFilter::Lt(parse_or_err(args[1])?)),
            "gte" => Ok(OrdFilter::Gte(parse_or_err(args[1])?)),
            "lte" => Ok(OrdFilter::Lte(parse_or_err(args[1])?)),
            _ => Err(format!("Invalid filter {}", value))
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

    // let filter = LogFilter {
    //     user_agent: StringFilter::Any,
    //     ip: EqFilter::Eq(IpAddr::V4(Ipv4Addr::new(193, 105, 7, 171))),
    //     timestamp: OrdFilter::Any, // OrdFilter::Gt(DateTime::parse_from_rfc3339("2023-02-12T14:34:20+00:00")?),
    // };

    // let file = File::open("raw/data-1.log")?;
    // let reader = std::io::BufReader::new(file);
    // let lines = reader
    //     .lines()
    //     .filter(|l| l.as_ref().is_ok_and(|l| !l.is_empty()))
    //     .map(|l| l.unwrap());
    // for line in lines {
    //     let entry = parse(LogType::CombinedLog, &line)?;
    //     if let LogEntry::CombinedLog(entry) = entry {
    //         if entry.is_match(&filter) {
    //             println!("{}", line);
    //         }
    //     }
    // }

    Ok(())
}
