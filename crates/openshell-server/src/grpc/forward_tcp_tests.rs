// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ForwardTcp` bridge lifetime: the relay and its connection slot end with either side.
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn data(bytes: &[u8]) -> TcpForwardFrame {
    TcpForwardFrame {
        payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Data(
            bytes.to_vec(),
        )),
    }
}

#[tokio::test]
async fn cancelled_client_ends_bridge_while_sandbox_side_is_idle() {
    // The sandbox side stays open and silent, like a keep-alive HTTP server.
    let (relay, _sandbox_side) = tokio::io::duplex(1024);
    let (client_frames, inbound) = mpsc::channel(8);
    let inbound = ReceiverStream::new(inbound);
    let (tx, rx) = mpsc::channel(8);
    let bridge = tokio::spawn(async move {
        bridge_forward_tcp_stream(inbound, relay, tx, "sandbox", "channel").await;
    });
    drop(client_frames);
    drop(rx);
    tokio::time::timeout(Duration::from_secs(5), bridge)
        .await
        .expect("a cancelled client releases its relay")
        .unwrap();
}

#[tokio::test]
async fn bridge_relays_both_directions_until_the_sandbox_closes() {
    let (relay, mut sandbox_side) = tokio::io::duplex(1024);
    let (client_frames, inbound) = mpsc::channel(8);
    let inbound = ReceiverStream::new(inbound);
    let (tx, mut rx) = mpsc::channel(8);
    let bridge = tokio::spawn(async move {
        bridge_forward_tcp_stream(inbound, relay, tx, "sandbox", "channel").await;
    });
    client_frames.send(Ok(data(b"ping"))).await.unwrap();
    let mut request = [0u8; 4];
    sandbox_side.read_exact(&mut request).await.unwrap();
    assert_eq!(&request, b"ping");
    sandbox_side.write_all(b"pong").await.unwrap();
    let reply = rx.recv().await.unwrap().unwrap();
    assert!(matches!(
        reply.payload,
        Some(openshell_core::proto::tcp_forward_frame::Payload::Data(ref bytes)) if bytes == b"pong"
    ));
    drop(sandbox_side);
    tokio::time::timeout(Duration::from_secs(5), bridge)
        .await
        .expect("a closed sandbox side ends the bridge")
        .unwrap();
}
