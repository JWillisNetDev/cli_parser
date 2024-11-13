use access_log_parser::{parse, CombinedLogEntry, LogEntry, LogType};
use chrono::{DateTime, FixedOffset};
use std::{boxed::Box, cmp::Ordering, fs::File, io::BufRead, net::{IpAddr, Ipv4Addr}};

type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
enum Filter<T> {
    None,
    Any,
    Eq(T),
    Gt(T),
    Gte(T),
    Lt(T),
    Lte(T),
}

impl<T> std::default::Default for Filter<T> {
    fn default() -> Self {
        Self::Any
    }
}

trait EqFilterable<T: PartialEq> {
    fn apply_eq_filter(&self, filter: &Filter<T>) -> bool;
}

impl<T: PartialEq> EqFilterable<T> for T {
    fn apply_eq_filter(&self, filter: &Filter<T>) -> bool {
        match filter {
            Filter::None => false,
            Filter::Any => true,
            Filter::Eq(value) => self == value,
            _ => false,
        }
    }
}

impl<T: PartialEq> EqFilterable<T> for Option<T> {
    fn apply_eq_filter(&self, filter: &Filter<T>) -> bool {
        match filter {
            Filter::Any => true,
            Filter::None => self.is_none(),
            Filter::Eq(value) => self.as_ref() == Some(value),
            _ => false,
        }
    }
}

trait OrdFilterable<T: PartialOrd> {
    fn apply_ord_filter(&self, filter: &Filter<T>) -> bool;
}

impl<T: PartialOrd> OrdFilterable<T> for T {
    fn apply_ord_filter(&self, filter: &Filter<T>) -> bool {
        match filter {
            Filter::None => false,
            Filter::Any => true,
            Filter::Eq(value) => self == value,
            Filter::Gt(value) => self > value,
            Filter::Gte(value) => self >= value,
            Filter::Lt(value) => self < value,
            Filter::Lte(value) => self <= value,
        }
    }
}

impl<T: PartialOrd> OrdFilterable<T> for Option<T> {
    fn apply_ord_filter(&self, filter: &Filter<T>) -> bool {
        match filter {
            Filter::Any => true,
            Filter::None => self.is_none(),
            Filter::Eq(value) => self.as_ref() == Some(value),
            Filter::Gt(value) => self.as_ref().map_or(false, |v| v > value),
            Filter::Gte(value) => self.as_ref().map_or(false, |v| v >= value),
            Filter::Lt(value) => self.as_ref().map_or(false, |v| v < value),
            Filter::Lte(value) => self.as_ref().map_or(false, |v| v <= value),
        }
    }
}

#[derive(Default)]
struct LogFilter {
    ip: Filter<IpAddr>,
    timestamp: Filter<DateTime<FixedOffset>>,
}

impl PartialEq<CombinedLogEntry<'_>> for LogFilter {
    fn eq(&self, other: &CombinedLogEntry) -> bool {
        other.ip.apply_eq_filter(&self.ip)
            && other.timestamp.apply_ord_filter(&self.timestamp)
    }
}

fn main() -> Result<(), Error> {
    let filter = LogFilter {
        ip: Filter::Any,
        timestamp: Filter::Gt(DateTime::parse_from_rfc3339("2023-02-12T14:34:05+00:00")?),
    };

    let file = File::open("raw/data-1.log")?;
    let reader = std::io::BufReader::new(file);
    let lines = reader
        .lines()
        .filter(|l| l.as_ref().is_ok_and(|l| !l.is_empty()))
        .map(|l| l.unwrap());
    for line in lines {
        let entry = parse(LogType::CombinedLog, &line)?;

        if let LogEntry::CombinedLog(log) = entry {
            if filter.eq(&log) {
                println!("{line}");
            }
        }
    }

    Ok(())
}
