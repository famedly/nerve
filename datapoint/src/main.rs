//! Datapoint server.
//!
//! TCP protocol:
//!   - Client sends a single header byte: the stride size in bytes
//!     (0x00 is interpreted as 256).
//!   - The header stride must match the server's configured stride
//!     exactly; otherwise the connection is closed immediately.
//!   - Afterwards the client streams raw, back-to-back datapoints of
//!     `stride` bytes each. The server appends them to a single
//!     temporary file, possibly interleaving stride-sized records
//!     coming from different clients (each datapoint write is atomic
//!     w.r.t. other clients because writes happen on a single thread).
//!
//! Cat mode:
//!   - Reads the temporary file and streams it to stdout.

use std::collections::HashMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};

const LISTENER: Token = Token(0);
const DEFAULT_ADDR: &str = "0.0.0.0:9000";
const READ_BUF_SIZE: usize = 64 * 1024;
const EVENT_CAPACITY: usize = 1024;

fn default_file_path() -> PathBuf {
    env::temp_dir().join("datapoint.bin")
}

fn print_usage(prog: &str) {
    eprintln!("Usage:");
    eprintln!("  {prog} serve <stride> [addr] [file]");
    eprintln!("  {prog} cat [file]");
    eprintln!();
    eprintln!("  stride  1..=256 byte size of one datapoint (0 means 256)");
    eprintln!("  addr    listen address, default {DEFAULT_ADDR}");
    eprintln!(
        "  file    temp file path, default {}",
        default_file_path().display()
    );
}

fn main() -> ExitCode {
    let mut args = env::args();
    let prog = args.next().unwrap_or_else(|| "datapoint".to_string());
    let args: Vec<String> = args.collect();

    let Some(cmd) = args.first() else {
        print_usage(&prog);
        return ExitCode::from(2);
    };

    let rest = &args[1..];
    let result = match cmd.as_str() {
        "serve" => run_serve(&prog, rest),
        "cat" => run_cat(rest),
        "-h" | "--help" | "help" => {
            print_usage(&prog);
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage(&prog);
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_serve(prog: &str, args: &[String]) -> io::Result<()> {
    let Some(stride_arg) = args.first() else {
        print_usage(prog);
        return Err(io::Error::new(ErrorKind::InvalidInput, "missing <stride>"));
    };

    let stride = parse_stride(stride_arg)?;
    let addr: SocketAddr = args
        .get(1)
        .map(String::as_str)
        .unwrap_or(DEFAULT_ADDR)
        .parse()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("invalid addr: {e}")))?;
    let file_path = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(default_file_path);

    serve(stride, addr, &file_path)
}

fn run_cat(args: &[String]) -> io::Result<()> {
    let file_path = args
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(default_file_path);
    cat(&file_path)
}

fn parse_stride(s: &str) -> io::Result<usize> {
    let n: u16 = s
        .parse()
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "stride must be 0..=256"))?;
    match n {
        0 => Ok(256),
        1..=256 => Ok(n as usize),
        _ => Err(io::Error::new(
            ErrorKind::InvalidInput,
            "stride must be 0..=256 (0 means 256)",
        )),
    }
}

fn cat(path: &Path) -> io::Result<()> {
    let mut f = File::open(path)?;
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    io::copy(&mut f, &mut stdout)?;
    stdout.flush()
}

/// Per-connection state.
struct Connection {
    stream: TcpStream,
    /// True once the stride header byte has been received & validated.
    got_header: bool,
    /// Bytes received but not yet flushed because they don't form a
    /// full datapoint. Capped at `stride - 1` between writes.
    pending: Vec<u8>,
}

fn serve(stride: usize, addr: SocketAddr, file_path: &Path) -> io::Result<()> {
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(EVENT_CAPACITY);

    let mut listener = TcpListener::bind(addr)?;
    poll.registry()
        .register(&mut listener, LISTENER, Interest::READABLE)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)?;

    eprintln!(
        "datapoint: listening on {} (stride={}, file={})",
        addr,
        stride,
        file_path.display()
    );

    let mut connections: HashMap<Token, Connection> = HashMap::new();
    let mut next_token: usize = 1;
    let mut read_buf = vec![0u8; READ_BUF_SIZE];

    loop {
        if let Err(e) = poll.poll(&mut events, None) {
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }

        for event in events.iter() {
            match event.token() {
                LISTENER => accept_all(&listener, &poll, &mut connections, &mut next_token)?,
                token => {
                    handle_connection(
                        token,
                        &mut connections,
                        &poll,
                        stride,
                        &mut read_buf,
                        &mut file,
                    )?;
                }
            }
        }
    }
}

fn accept_all(
    listener: &TcpListener,
    poll: &Poll,
    connections: &mut HashMap<Token, Connection>,
    next_token: &mut usize,
) -> io::Result<()> {
    loop {
        match listener.accept() {
            Ok((mut stream, _peer)) => {
                let token = Token(*next_token);
                *next_token = next_token.wrapping_add(1);
                if *next_token == 0 {
                    // Skip the reserved LISTENER token if we ever wrap.
                    *next_token = 1;
                }
                poll.registry()
                    .register(&mut stream, token, Interest::READABLE)?;
                connections.insert(
                    token,
                    Connection {
                        stream,
                        got_header: false,
                        pending: Vec::new(),
                    },
                );
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("accept error: {e}");
                return Ok(());
            }
        }
    }
}

fn handle_connection(
    token: Token,
    connections: &mut HashMap<Token, Connection>,
    poll: &Poll,
    stride: usize,
    read_buf: &mut [u8],
    file: &mut File,
) -> io::Result<()> {
    let mut close = false;

    if let Some(conn) = connections.get_mut(&token) {
        loop {
            match conn.stream.read(read_buf) {
                Ok(0) => {
                    close = true;
                    break;
                }
                Ok(n) => {
                    let mut chunk = &read_buf[..n];

                    if !conn.got_header {
                        // chunk is non-empty here (n >= 1).
                        let header = chunk[0];
                        let client_stride = if header == 0 { 256 } else { header as usize };
                        chunk = &chunk[1..];
                        if client_stride != stride {
                            // Stride mismatch: drop the connection.
                            close = true;
                            break;
                        }
                        conn.got_header = true;
                    }

                    if chunk.is_empty() {
                        continue;
                    }

                    // Flush as many full stride-sized datapoints as
                    // possible directly from `pending + chunk` to the
                    // file, keeping only the trailing partial
                    // datapoint in `pending`.
                    if conn.pending.is_empty() {
                        let full = (chunk.len() / stride) * stride;
                        if full > 0 {
                            file.write_all(&chunk[..full])?;
                        }
                        if full < chunk.len() {
                            conn.pending.extend_from_slice(&chunk[full..]);
                        }
                    } else {
                        // We had a leftover partial datapoint; complete
                        // it first if we can, then flush new full ones.
                        let need = stride - conn.pending.len();
                        if chunk.len() < need {
                            conn.pending.extend_from_slice(chunk);
                        } else {
                            conn.pending.extend_from_slice(&chunk[..need]);
                            // pending now holds exactly one datapoint.
                            file.write_all(&conn.pending)?;
                            conn.pending.clear();

                            let rest = &chunk[need..];
                            let full = (rest.len() / stride) * stride;
                            if full > 0 {
                                file.write_all(&rest[..full])?;
                            }
                            if full < rest.len() {
                                conn.pending.extend_from_slice(&rest[full..]);
                            }
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    close = true;
                    break;
                }
            }
        }
    }

    if close && let Some(mut conn) = connections.remove(&token) {
        let _ = poll.registry().deregister(&mut conn.stream);
        // Any bytes still in `conn.pending` are an incomplete
        // datapoint and are intentionally discarded so the temp
        // file only ever contains aligned, complete records.
    }

    Ok(())
}
