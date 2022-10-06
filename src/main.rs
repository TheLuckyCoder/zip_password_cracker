use bruteforce::charset::Charset;
use bruteforce::BruteForce;
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use std::fs::File;
use std::io::Read;
use std::os::unix::prelude::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{fs, thread};
use zip::ZipArchive;

const DEFAULT_CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, help = "The encrypted ZIP file")]
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

    let file_path = Path::new(args.file.as_str());
    if !file_path.exists() {
        eprintln!("Specified file does not exist {}", args.file)
    }

    println!("Starting to bruteforce password using {thread_count} threads");

    thread::scope(|s| {
        let is_alive = Arc::new(AtomicBool::new(true));
        let (sender, receiver) = bounded::<String>(thread_count * 128);

        let is_alive_clone = is_alive.clone();
        s.spawn(move || {
            generate_passwords(
                sender,
                is_alive_clone,
                args.charset.as_str(),
                args.min_length,
            )
        });

        for i in 0..thread_count {
            let receiver = receiver.clone();
            let is_alive = is_alive.clone();

            thread::Builder::new()
                .name(format!("checker-{i}"))
                .spawn_scoped(s, move || {
                    password_checker(receiver, is_alive, file_path, args.verbose)
                })
                .expect("Failed to start thread");
        }
    });
}

fn generate_passwords(
    sender: Sender<String>,
    is_alive_clone: Arc<AtomicBool>,
    charset: &str,
    min_length: usize,
) {
    let brute_force = BruteForce::new_at(Charset::new_by_str(charset), min_length);

    for pass in brute_force {
        if !is_alive_clone.load(Ordering::Relaxed) {
            break;
        }

        match sender.send(pass) {
            Ok(_) => {}
            Err(_) => break, // channel disconnected, stop thread
        }
    }
}

fn password_checker(
    receiver: Receiver<String>,
    is_alive: Arc<AtomicBool>,
    file_path: &Path,
    verbose: bool,
) {
    let file = File::open(file_path).expect("File should exist");
    let mut archive = ZipArchive::new(file).expect("Archive already validated");
    let mut read_buffer = Vec::with_capacity(fs::metadata(file_path).unwrap().size() as usize);

    while is_alive.load(Ordering::Relaxed) {
        match receiver.recv() {
            Err(_) => break,
            Ok(password) => {
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
                                println!("Password found: {password}")
                            }
                        }
                        read_buffer.clear()
                    }
                }
            }
        }
    }
}
