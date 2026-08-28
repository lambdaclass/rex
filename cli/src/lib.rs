#![warn(warnings, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![recursion_limit = "256"]

pub mod cli;
mod commands;
mod common;
mod utils;
mod verify;
