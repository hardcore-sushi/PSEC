## Warning !
I'm not a professional cryptographer. This protocol is very new and didn't receive any security audit. Therefore, it __shouldn't be considered fully secure__. I don't provide any warranty about its robustness.

If you have some knowledge about cryptography I would be very happy to have your feedback. If you find weaknesses or if you think it's secure, please tell me.

# PSEC Protocol
### Peer to peer Secure Ephemeral Communication

PSEC protocol is a simplification/adaptation of TLS 1.3 for P2P. The goal is to provide an encrypted and authenticated secure transport layer for ephemeral P2P communications. PSEC should ensure plaintext length obfuscation, deniability, forward secrecy and future secrecy. If you think it doesn't, please inform me.

Since there no central server in P2P communication, there is no certificate. Instead, peers use long term Ed25519 identity keys `idK` for authentication. And because there is no client/server model, a mutual consensus will be needed for some computations. This consensus is obtained by simply comparing received and sent bytes during the very first part of the handshake. The peer who has sent the lowest value will get a boolean set to `true` and the other will have it set to `false`. It's like determining who will play the role of the server and who will play that of the client.

To simplify explanations, I will describe what's happen when a peer (let's say Alice) wants to establish a secure communication with another peer (Bob). This protocol has been built so that two peers can establish a secure communication by running the same code. Therefore, all that Alice will do will also be done by Bob. 

## ECDHE Exchange
The first thing that Alice do after establishing connection is to generate an ephemeral x25519 key pair `alice_ephK` and send the public key `alice_ephK_pub` to Bob. Along side with the public key, Alice sends 64 random bytes to increase the handshake entropy. Once Alice and Bob exchanged their public keys, they do a Diffie Hellman computation to get a 32 bytes long `shared_secret`. From Alice's side:
```
shared_secret = ed25519_diffie_hellman(
    private_key: alice_ephK_priv,
    public_key: bob_ephK_pub
)
```
At this point, the ephemeral private keys of both parties are no more useful and can be safely deleted. However, the public keys must be kept to verify their authenticity later.

The mutual consensus is obtained by comparing bytes sent by each parties (64 random bytes & ephemeral public keys). Note that the 64 random bytes are compared first. Here is an example of this consensus in python:
```
for i in range(64+PUBLIC_KEY_LENGTH):
    if bytes_sent[i] != bytes_received[i]:
        i_play_the_role_of_the_server = bytes_sent[i] < bytes_received[i]
        break
```

## Handshake Keys Derivation
Alice will then compute the `handshake_secret` which is the output of the HKDF Extract operation on the `shared_secret` using the SHA384 hash function:
```
handshake_secret = HKDF_extract(
    salt: None,
    ikm: shared_secret
)
```
This value is therefore common to Alice and Bob.
 
She will also compute `handsake_hash`, a SHA384 hash of all previous messages sent through the connection. For Alice and Bob have the same `handshake_hash`, the order of the messages in the hash input is determined by the mutual consensus.
```
if i_play_the_role_of_the_server:
    ordered_bytes = bytes_received + bytes_sent
else:
    ordered_bytes = bytes_sent + bytes_received
handshake_hash = SHA384(ordered_bytes)
```
With the `handshake_secret` and the `handshake_hash`, Alice computes the `local_handshake_traffic_secret` using the HKDF Expand Label function as follows:
```
local_handshake_traffic_secret = HKDF_expand_label(
    key: handshake_secret,
    label: handshake_local_label,
    context: handhsake_hash
)
```
 `handshake_local_label` is a known value which depend on the mutual consensus and is unique to this operation. It corresponds to the `handshake_peer_label` of Bob.

In the same way, Alice will compute the `peer_handshake_traffic_secret` by replacing `handshake_local_label` with `handshake_peer_label`. That way, it will match the Bob's `local_handshake_traffic_secret`. These two values are 48 bytes long, as an output of SHA384 function.

With this two secrets, Alice will be able to derive her encryption key and IV in this way:
```
local_handshake_key = HKDF_expand_label(
    key: local_handshake_traffic_secret,
    label: "key",
    context: None
)

local_handshake_iv = HKDF_expand_label(
    key: local_handshake_traffic_secret,
    label: "iv",
    context: None
)
```
She will also do this operations with `peer_handshake_traffic_secret` as the _key_ value to derive Bob's encryption key and IV.

Now, Alice and Bob can start talking using AES-GCM 128 bits encryption. Keys are 16 bytes long (128 bits), IV 12 bytes long (96 bits) and GCM tags 16 bytes long (128 bits).

## Authentication
At this point, every messages are sent encrypted with the previous derived handshake keys. AES-GCM nonces are obtained by XORing a 8 bytes counter to the last 8 bytes of the IV. The counter is specific to the IV. It's initialized to 0 and incremented by 1 with each use. Here is a python implementation of this nonce generation:
```
def iv_to_nonce(iv, counter):
    counter_bytes = b"\x00"*4 + counter.to_bytes(8, byteorder="big")
    return bytes([i ^ j for i, j in zip(iv, counter_bytes)])
```

Alice will first send again 64 random bytes. Then, she will send her identity public key `alice_idK_pub` and a signature of his ephemeral public key `alice_ephK_pub` used at the first stage of the handshake.
```
alice_idK_pub + ed25519_sign(
    private_key: alice_idK_priv,
    data: alice_ephK_pub
)
```

Bob will do the same and Alice will verify whether the ephemeral public key `bob_ephK_pub` sent by Bob earlier match the received signature. If they don't match, the handshake is aborted. Otherwise, Alice can check if the Bob's identity public key `bob_idK_pub` is already known and matches one of her contacts or if Bob is a new unknown person.
```
if ed_22519_verify(
    public_key: bob_idK_pub,
    data: bob_ephK_pub
):
    is_already_know(bob_idK_pub)
    // continue handshake
else:
    //abort handshake
```

## Handshake finished
A new hash of the handshake is computed to include the authentication step. Alice will then compute a HMAC of this hash to agree with Bob that the handshake has not been corrupted. The 48 bytes long HMAC key is computed using HKDF Expand Label:
```
local_key = HKDF_expand_label(
    key: local_handshake_traffic_secret,
    label: "finished",
    context: None
)

local_handshake_finished = HMAC(
    hash: SHA384,
    key: local_key,
    data: handshake_hash
)
```
Alice sends the HMAC output in __plain text__ and receive the Bob's one. She can verify it using her `peer_handshake_traffic_secret`:
```
peer_key = HKDF_expand_label(
    key: peer_handshake_traffic_secret,
    label: "finished",
    context: None
)

peer_handshake_finished = HMAC(
    hash: SHA384,
    key: peer_key,
    data: handshake_hash,
)

assert(received_handshake_finished == peer_handshake_finished)
```
If the Bob's HMAC doesn't match, the handshake is aborted.

## Application Keys Derivation
Once Alice and Bob agreed that the handshake was valid, they will compute the keys that will be used to send application data. First, Alice compute a 48 bytes long `derived_secret`:
```
derived_secret = HKDF_expand_label(
    key: handshake_secret,
    label: "derived",
    context: None
)
```
From this `derived_secret`, a 48 bytes long `master_secret` is computed:
```
master_secret = HKDF_extract(
    salt: derived_secret,
    ikm: ""
)
```
Then, Alice compute her `local_application_traffic_secret` and `peer_application_traffic_secret` as follows:
```
local_application_traffic_secret = HKDF_expand_label(
    key: master_secret,
    label: application_local_label,
    context: handshake_hash
)

peer_application_traffic_secret = HKDF_expand_label(
    key: master_secret,
    label: application_peer_label,
    context: handshake_hash
)
```
`application_local_label` and `application_peer_label` also depend on the mutual consensus and are unique to this step.

Application encryption keys and IVs are finally derived from the two secrets in the same way as the handshake's ones:
```
local_application_key = HKDF_expand_label(
    key: local_application_traffic_secret,
    label: "key",
    context: None
)

local_application_iv = HKDF_expand_label(
    key: local_application_traffic_secret,
    label: "iv",
    context: None
)
```
The Bob's ones are obtained by replacing `local_application_traffic_secret` with `peer_application_traffic_secret`. Keys and IVs lengths are the same as the handshake's ones.

## Secure communication
At this point, the handshake is finished. Alice and Bob can now talk securely using AES-GCM 128 bits.

When Alice wants to send a message, she will first pad the plaintext to obfuscate his length. To distinguish the real plaintext from the padding, she encodes it's length and prefix it to the message. The targeted padded length is constant (1000 bytes in this example). If the plaintext length is larger than this value, it's increased (multiplied by 2 in this example) until the plaintext can fit. Here is a python implementation of this padding process:
```
plaintext = "Hello Bob !"
plaintext_encoded_length = len(plaintext).to_bytes(4, byteorder="big")

padded_length = 1000
while padded_length < len(plaintext) + len(plaintext_encoded_length):
    padded_length = padded_length * 2

padded_message = plaintext_encoded_length + message + os.urandom(padded_length-len(plaintext) + len(plaintext_encoded_length))
```
Once the plaintext is padded, Alice encrypts it with her `local_application_key`. The AES nonce is computed from `local_application_iv` in the same way than during the handshake authentication phase. Alice add the padded message length as an additional associated data to the AES GCM encrypt function. Therefore, message lengths are authenticated and cannot be tampered.
```
nonce = iv_to_nonce(local_counter)
local_counter += 1
cipher_text = AES_128_GCM.encrypt(
    key: local_application_key,
    nonce: nonce,
    plaintext: padded_message,
    aad: len(padded_message).to_bytes(4, byteorder="big")
)
```

When Alice receive a message, she reads the first few bytes to get the message length and then wait for the full message to be received. Once received the exact length, Alice can decrypt the message with her `peer_application_key` and verify the authenticity of the message (length and content).
```
nonce = iv_to_nonce(peer_counter)
peer_counter += 1
padded_plaintext = AES_128_GCM.decrypt(
    key: peer_application_key,
    nonce: nonce,
    cipher_text: received_cipher_text,
    aad: received_message_length
)
```
Then, Alice reads the first bytes of the padded plaintext to get the actual length of the unpadded plaintext. Thus, she just have to read the first N bytes of the padded plaintext and discard the remaining bytes. An example of this unpadding process in python:
```
actual_encoded_length = padded_plaintext[:4]
actual_length = int.from_bytes(actual_encoded_length, byteorder="big")
unpadded_plaintext = padded_plaintext[4:4+actual_length]
```

# Conclusion
AFAIK, the PSEC protocol provide all expected properties described earlier:
- Peers authentication is insured by ECDHE exchange and Ed25519 signatures with peers' long term identity keys.
- Messages encryption and authentication are insured by AES-GCM.
- Plaintext lengths are obfuscated using padding.
- Since all parties have the necessary keys to create any arbitrary messages, all sent messages can be denied.
- As far as the communications are ephemeral, forward secrecy is insured: encryption keys are derived from ephemeral keys `ephK`.
- If the ephemeral keys `ephK` are generated using a strong cryptographically secure PRNG, future secrecy is insured.
