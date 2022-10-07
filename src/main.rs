#![feature(iter_collect_into)]

use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, thread};

use bruteforce::charset::Charset;
use bruteforce::BruteForce;
use clap::Parser;
use concurrent_queue::{ConcurrentQueue, PushError};
use zip::ZipArchive;

const DEFAULT_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, help = "The encrypted ZIP file", default_value_t = String::from("/home/razvanf/Downloads/hello.zip"))]
    pub file: String,
    #[arg(short, long, help = "Enables some extra logging")]
    pub verbose: bool,
    #[arg(short, long, default_value_t = String::from(DEFAULT_CHARSET))]
    pub charset: String,
    #[arg(
        short('l'),
        long,
        default_value_t = 1,
        help = "The minimum length of the password"
    )]
    pub min_length: usize,
    #[arg(
        short,
        long,
        default_value_t = 0,
        help = "Number of threads to use, 0 defaults to the number of CPU cores"
    )]
    pub thread_count: usize,
}

fn main() {
    let args = Args::parse();
    let thread_count = if args.thread_count == 0 {
        thread::available_parallelism().unwrap().get()
    } else {
        args.thread_count
    };

    let zip_file = Cursor::new(
        fs::read(&args.file)
            .unwrap_or_else(|_| panic!("Failed reading the ZIP file: {}", args.file)),
    );

    println!("Starting to bruteforce password using {thread_count} threads");
    let start = Instant::now();

    thread::scope(|s| {
        let is_alive = Arc::new(AtomicBool::new(true));
        let queue: Queue = Arc::new(ConcurrentQueue::bounded(thread_count * 4));

        let is_alive_clone = is_alive.clone();
        let queue_clone = queue.clone();
        s.spawn(move || {
            let passwords_generated = generate_passwords(
                queue_clone,
                is_alive_clone,
                args.charset.as_str(),
                args.min_length,
            );

            let stop = start.elapsed();
            let elapsed_secs = stop.as_secs();
            let per_second = passwords_generated as f64 / elapsed_secs as f64;
            println!(
                "Generated {passwords_generated} in {elapsed_secs} seconds ({per_second} passwords/s)"
            );
        });

        thread::sleep(Duration::from_millis(10));

        for i in 0..thread_count {
            let is_alive = is_alive.clone();
            let cursor = zip_file.clone();
            let queue = queue.clone();

            thread::Builder::new()
                .name(format!("checker-{i}"))
                .spawn_scoped(s, move || {
                    password_checker(queue, is_alive, cursor, args.verbose)
                })
                .expect("Failed to start thread");
        }
    });
}

type Queue = Arc<ConcurrentQueue<Vec<String>>>;

fn generate_passwords(
    concurrent_queue: Queue,
    is_alive: Arc<AtomicBool>,
    charset: &str,
    min_length: usize,
) -> usize {
    const CAPACITY: usize = 8192;
    let mut brute_force = BruteForce::new_at(Charset::new_by_str(charset), min_length);

    let mut passwords_generated = 0usize;
    while is_alive.load(Ordering::Relaxed) {
        let mut passwords: Vec<String> = Vec::with_capacity(CAPACITY);
        for _ in 0..CAPACITY {
            passwords.push(brute_force.raw_next().to_string());
        }

        while is_alive.load(Ordering::Relaxed) {
            match concurrent_queue.push(passwords) {
                Ok(_) => break,
                Err(e) => match e {
                    PushError::Full(value) => passwords = value, // Retry until we are able to push
                    PushError::Closed(_) => {
                        is_alive.store(false, Ordering::Relaxed);
                        break; // channel disconnected, stop thread
                    }
                },
            }
            thread::yield_now();
        }
        passwords_generated += CAPACITY;
    }

    passwords_generated
}

fn password_checker(
    queue: Queue,
    is_alive: Arc<AtomicBool>,
    mut zip_file: Cursor<Vec<u8>>,
    verbose: bool,
) {
    let mut read_buffer = Vec::with_capacity(zip_file.get_ref().len());
    let mut archive = ZipArchive::new(&mut zip_file).expect("File should exist");

    while is_alive.load(Ordering::Relaxed) {
        match queue.pop() {
            Err(_) => break,
            Ok(passwords) => {
                for password in passwords {
                    let res = archive
                        .by_index_decrypt(0, password.as_bytes())
                        .expect("Unexpected error");

                    match res {
                        Err(_) => (), // invalid password
                        Ok(mut zip) => {
                            if zip.size() as usize > read_buffer.capacity() {
                                read_buffer.reserve(read_buffer.capacity() - zip.size() as usize);
                            }

                            if verbose {
                                println!(
                                    "Potential password found: {password}. Checking the entire archive..."
                                );
                            }
                            match zip.read_to_end(&mut read_buffer) {
                                Err(_) => (), // password collision
                                Ok(_) => {
                                    is_alive.store(false, Ordering::Relaxed);
                                    println!("Password found: {password}");
                                    break;
                                }
                            }
                            read_buffer.clear()
                        }
                    }
                }
            }
        }
    }
}
