# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WhatsApp-Rust is a high-performance, asynchronous Rust library for interacting with the WhatsApp platform. It implements the WhatsApp binary protocol, Noise Protocol handshake, Signal Protocol for E2E encryption, and media handling.

## Architecture

The project uses a three-crate architecture:

- **wacore**: Platform-agnostic core library (`no_std` compatible) containing binary protocol, cryptography, and state management traits
- **waproto**: Protocol Buffers definitions generated from `whatsapp.proto` using prost
- **whatsapp-rust** (main): High-level client integrating wacore with Tokio runtime, Diesel SQLite persistence, and client API

### Key Components

- **Client** (`src/client.rs`): Connection lifecycle orchestration and event bus
- **PersistenceManager** (`src/store/persistence_manager.rs`): State management gatekeeper
- **Signal Protocol** (`wacore/src/libsignal/` & `src/store/signal*.rs`): E2E encryption implementation
- **Socket & Handshake** (`src/socket/`, `src/handshake.rs`): WebSocket connection and Noise Protocol handshake
- **Media** (`src/download.rs`, `src/upload.rs`, `src/mediaconn.rs`): Media handling with encryption/decryption

## Development Commands

### Building
```bash
cargo build                    # Build all crates
cargo build --release         # Release build
```

### Testing
```bash
cargo test --all              # Run all tests
cargo test [TESTNAME]         # Run specific test
```

### Code Quality
```bash
cargo fmt                     # Format code
cargo clippy --all-targets    # Lint all targets
```

### Protocol Buffer Generation
```bash
GENERATE_PROTO=1 cargo build -p waproto  # Regenerate protobuf definitions
```

## Critical Development Patterns

### State Management
- **Never modify Device state directly**
- Use `DeviceCommand` + `PersistenceManager::process_command()` for modifications
- Use `PersistenceManager::get_device_snapshot()` for read-only access

### Async Programming
- All I/O uses Tokio runtime
- Use `Client::chat_locks` to serialize per-chat operations to prevent race conditions
- **Wrap all blocking I/O (`ureq` calls) and CPU-bound tasks (media encryption) in `tokio::task::spawn_blocking`**

### Media Operations
- `Downloadable` trait provides generic interface for downloadable media
- `MediaConn` manages media server connections - always refresh if expired
- Media encryption/decryption handled in download/upload modules

### Error Handling
- Use `thiserror` for custom errors (`SocketError`, etc.)
- Use `anyhow::Error` for functions with multiple failure modes
- Avoid `.unwrap()` and `.expect()` outside tests and unrecoverable paths

## Key Files for Understanding

- `src/client.rs`: Central client hub
- `src/store/persistence_manager.rs`: State change gatekeeper
- `src/message.rs`: Incoming message decryption pipeline
- `src/send.rs`: Outgoing message encryption pipeline
- `src/download.rs` / `src/upload.rs`: Media handling
- `src/mediaconn.rs`: Media server management
- `waproto/src/whatsapp.proto`: Message structure definitions

## Database

Uses Diesel ORM with SQLite for persistence:
- Schema defined in `src/store/schema.rs`
- Migrations in `./migrations` directory
- Configuration in `diesel.toml`

## Protocol Reference

When in doubt, refer to the **whatsmeow** Go library as the source of truth for protocol implementation details.