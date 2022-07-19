# TNLS-gateways

```mermaid
flowchart LR
      A[User Client]-->B(Public Contract);
      B-->C{Public Gateway};
      C-->D(((Relay Network)));
      D-->E{Private Gateway};
      E-->F(Private Contract);
      F-->E;
      E-->D;
      D-->C;
      C-->B;
      B-->A;
      style E stroke:#d83,stroke-width:3px;
```

## Private Gateway Interfaces

```rust
pub struct PreExecutionMsg {
    /// Task ID coming from the relayer.
    pub task_id: u64,
    /// Handle to be called at destination contract.
    pub handle: String,
    /// Destination contract address and code hash.
    pub routing_info: Contract,
    /// Encryption of (data, routing info, and user address/verifying key). Includes additional data (AD).
    pub payload: Binary,
    /// Hash of unencrypted input values.
    pub payload_hash: Binary,
    /// Signature of hash of unencrypted input values.
    pub payload_signature: Binary,
    /// User verification key / public chain address.
    pub sender: Sender,
}

pub struct Contract {
    /// Contract address.
    pub address: HumanAddr,
    /// Contract code hash.
    pub hash: String,
}

pub struct Sender {
    /// User public chain address.
    pub address: HumanAddr,
    /// User verification key.
    pub public_key: Binary,
}
```

Before encryption / after decryption:
```rust
pub struct Payload {
    /// Input values as JSON formatted string.
    pub data: String,
    /// Destination contract on private network.
    pub routing_info: Contract,
    /// User verification key / public chain address.
    pub sender: Sender,
}
```
