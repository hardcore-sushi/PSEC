## Warning !
I'm not a professional cryptographer. This protocol is very new and didn't receive any security audit. Therefore, it __shouldn't be considered fully secure__. I don't provide any warranty about its robustness.

If you have some knowledge about cryptography I would be very happy to have your feedback. If you find weaknesses or if you think it's secure, please tell me.

PSEC is currently in alpha stage, at version 0.4. There is no guarantee that any version is compatible with previous ones. Be ready to make some changes to your code if you decide to implement the protocol right now.

# PSEC Protocol
### Peer to peer Secure Ephemeral Communications

PSEC protocol is a simplification/adaptation of TLS 1.3 for P2P networks. The goal is to provide an encrypted and authenticated secure transport layer for ephemeral P2P communications. PSEC should ensure message deniability, forward & future secrecy between communications, and optional plain text length obfuscation. If you think it doesn't, please inform me. The reference implementation in rust can be found [here](https://github.com/hardcore-sushi/async-psec).

Since there no central server in P2P communication, there is no certificate. Instead, peers use long term Ed25519 identity keys `idK` for authentication. And because there is no client/server model, a mutual consensus will be needed for some computations. This consensus is obtained by simply comparing received and sent bytes during the very first part of the handshake. The peer who sent the lowest value will get a boolean set to `true` and the other will have it set to `false`. It's like determining who will play the role of the server and who will play that of the client.

To simplify explanations, I will describe what's happen when a peer (let's say Alice) wants to establish a secure communication with another peer (Bob). This protocol was built so that two peers can establish a secure communication by running the same code. Therefore, all that Alice will do will also be done by Bob. 

## ECDHE Exchange
The first thing that Alice do after establishing connection is to generate an ephemeral x25519 key pair `alice_ephK` and send the 32 bytes public key `alice_ephK_pub` to Bob. Along side with the public key, Alice sends 64 random bytes to increase the handshake entropy.

|  random  |  public key |
|:--------:|:-----------:|
| 64 bytes |   32 bytes  |

Once Alice and Bob exchanged their public keys, they do a Diffie Hellman computation to get a 32 bytes long `shared_secret`. From Alice's side:
```python
shared_secret = ed25519_diffie_hellman(
    private_key=alice_ephK_priv,
    public_key=bob_ephK_pub
)
```
At this point, the ephemeral private keys of both parties are no more useful and can be safely deleted. However, the public keys must be kept to verify their authenticity later.

The mutual consensus is obtained by comparing bytes sent by each parties (64 random bytes & ephemeral public keys). Here is an example of this consensus in python:
```python
for i in range(64+32):
    if bytes_sent[i] != bytes_received[i]:
        i_play_the_role_of_the_server = bytes_sent[i] < bytes_received[i]
        break
```

## Handshake Keys Derivation
Key derivation relies on [HKDF](https://en.wikipedia.org/wiki/HKDF), used with the SHA384 hash function. HKDF expand operation is wrapped in `HKDF_expand_label`. Here is an implementation of this function using the [hkdf library](https://pypi.org/project/hkdf) in python:
```python
# key: already cryptographically strong pseudorandom key (minimum of 48 bytes)
# label: abritray string
# context: abritrary binary data
def HKDF_expand_label(key, label, context):
    info = len(label).to_bytes(4, byteorder="big")+label.encode()
    if context is not None:
        info += len(context).to_bytes(4, byteorder="big")+context
    return hkdf_expand(key, info=info, length=48, hash=hashlib.sha384)
```

Alice computes the `handshake_secret` which is the output of the HKDF Extract operation on the `shared_secret` using the SHA384 hash function:
```python
handshake_secret = hkdf_extract(
    salt=None,
    input_key_material=shared_secret
)
```
This value is therefore common to Alice and Bob. Now, `shared_secret` can be deleted.
 
She will also compute `handsake_hash`, a SHA384 hash of all previous messages sent through the connection. For Alice and Bob to have the same `handshake_hash`, the order of the messages in the hash input is determined by the mutual consensus.
```python
if i_play_the_role_of_the_server:
    ordered_bytes = bytes_received + bytes_sent
else:
    ordered_bytes = bytes_sent + bytes_received
handshake_hash = sha384(ordered_bytes).digest()
```
With the `handshake_secret` and the `handshake_hash`, Alice computes the `local_handshake_traffic_secret` using the HKDF Expand Label function as follows:
```python
local_handshake_traffic_secret = HKDF_expand_label(
    key=handshake_secret,
    label=handshake_local_label,
    context=handhsake_hash
)
```
`handshake_local_label` is a known value which depend on the mutual consensus and is unique to this operation. It corresponds to the `handshake_peer_label` of Bob. It's computed like this:
```python
handshake_local_label = "handshake_i_am_"
handshake_peer_label = "handshake_i_am_"
if i_play_the_role_of_the_server:
    handshake_local_label += "bob"
    handshake_peer_label += "alice"
else:
    handshake_local_label += "alice"
    handshake_peer_label += "bob"
```

In the same way, Alice will compute the `peer_handshake_traffic_secret` by replacing `handshake_local_label` with `handshake_peer_label`. That way, it will match the Bob's `local_handshake_traffic_secret`. These two values are 48 bytes long, as an output of the SHA384 function.

With this two secrets, Alice will be able to derive her encryption key and IV in this way:
```python
local_handshake_key = HKDF_expand_label(
    key=local_handshake_traffic_secret,
    label="key",
    context=None
)

local_handshake_iv = HKDF_expand_label(
    key=local_handshake_traffic_secret,
    label="iv",
    context=None
)
```
She will also do this operations with `peer_handshake_traffic_secret` as the _key_ value to derive Bob's encryption key and IV.

Now, Alice and Bob can start talking using AES-GCM 128 bits encryption. They will encrypt with `local_handshake_key` and decrypt with `peer_handshake_key`. Keys are 16 bytes long (128 bits), IV 12 bytes long (96 bits) and GCM tags 16 bytes long (128 bits).

## Authentication
Alice will create a message composed of new 64 random bytes, her long-term identity public key `alice_idK_pub` and a signature of his ephemeral public key `alice_ephK_pub` used at the first stage of the handshake.
```python
auth_msg = os.urandom(64) + alice_idK_pub + ed25519_sign(
    private_key=alice_idK_priv,
    data=alice_ephK_pub
)
```
|  random  | identity public key | signature of the ephemeral public key |
|:--------:|:-------------------:|:-------------------------------------:|
| 64 bytes |       32 bytes      |                64 bytes               |

This message is first encrypted with the previous derived handshake keys before being sent. The AES-GCM nonces are just the plain IVs as the handshake keys are only used once.
```python
encrypted_auth_msg = AES_128_GCM.encrypt(
    key=local_handshake_key,
    nonce=local_handshake_iv,
    plain_text=auth_msg
)
```
| encrypted auth message | AES-GCM tag |
|:----------------------:|:-----------:|
|        160 bytes       |   16 bytes  |

At this point, `alice_ephK_pub`, `local_handshake_key` and `local_handshake_iv` can be deleted. Once Alice received and decrypted the Bob message, `peer_handshake_key` and `peer_handshake_iv` can be deleted too.

Bob will do the same and Alice will verify whether the ephemeral public key `bob_ephK_pub` sent by Bob earlier match the received signature. If they don't match, the handshake is aborted. Otherwise, Alice can check if the Bob's identity public key `bob_idK_pub` is already known and matches one of her contacts or if Bob is a new unknown person.
```python
if ed_22519_verify(
    public_key=bob_idK_pub,
    data=bob_ephK_pub
):
    check_if_already_known(bob_idK_pub)
    # continue handshake
else:
    # abort handshake
```
Once verified, `bob_ephK_pub` can be deleted.

## Handshake finished
A new hash of the handshake is computed to include the authentication step. Alice will then compute a HMAC of this hash to agree with Bob that the handshake has not been corrupted. The 48 bytes long HMAC key is computed using HKDF Expand Label:
```python
local_key = HKDF_expand_label(
    key=local_handshake_traffic_secret,
    label="finished",
    context=None
)

local_handshake_finished = HMAC(
    hash=SHA384,
    key=local_key,
    data=handshake_hash
)
```
After this, `local_handshake_traffic_secret` can be deleted.

Alice sends the HMAC output `local_handshake_finished` in __plain text__ and receives the Bob's one.
| HMAC output |
|:-----------:|
|   48 bytes  |

She can verify it using her `peer_handshake_traffic_secret`:
```python
peer_key = HKDF_expand_label(
    key=peer_handshake_traffic_secret,
    label="finished",
    context=None
)

peer_handshake_finished = HMAC(
    hash=SHA384,
    key=peer_key,
    data=handshake_hash,
)

assert(received_handshake_finished == peer_handshake_finished)
```
`peer_handshake_traffic_secret` can be deleted. If the Bob's HMAC and the computed `peer_handshake_finished` don't match, the handshake is aborted.

## Application Keys Derivation
Once Alice and Bob agreed that the handshake was valid, they will compute the keys that will be used to send application data. First, Alice computes a 48 bytes long `derived_secret` from the previous `handshake_secret`:
```python
derived_secret = HKDF_expand_label(
    key=handshake_secret,
    label="derived",
    context=None
)
```
Now, `handshake_secret` can be deleted. From this `derived_secret`, a 48 bytes long `master_secret` is retreived:
```python
master_secret = hkdf_extract(
    salt=derived_secret,
    input_key_material=""
)
```
Then, `derived_secret` can be deleted and Alice computes her `local_application_traffic_secret` and `peer_application_traffic_secret` as follows:
```python
local_application_traffic_secret = HKDF_expand_label(
    key=master_secret,
    label=application_local_label,
    context=handshake_hash
)

peer_application_traffic_secret = HKDF_expand_label(
    key=master_secret,
    label=application_peer_label,
    context=handshake_hash
)
```
The `handshake_hash` is the same as in the [handshake verification step](#handshake-finished). Therefore, it doesn't include the verification HMACs.

`application_local_label` and `application_peer_label` depend on the mutual consensus and are unique to this step:
```python
application_local_label = "application_i_am_"
application_peer_label = "application_i_am_"
if i_play_the_role_of_the_server:
    application_local_label += "bob"
    application_peer_label += "alice"
else:
    application_local_label += "alice"
    application_peer_label += "bob"
```
At this point, `master_secret` can be deleted.

Application encryption keys and IVs are finally derived from the two secrets in the same way as the handshake's ones:
```python
local_application_key = HKDF_expand_label(
    key=local_application_traffic_secret,
    label="key",
    context=None
)

local_application_iv = HKDF_expand_label(
    key=local_application_traffic_secret,
    label="iv",
    context=None
)
```
The Bob's key and IV are obtained by replacing `local_application_traffic_secret` with `peer_application_traffic_secret`. Keys and IVs lengths are the same as the handshake's ones.

Once application keys are derived, `local_application_traffic_secret` and `peer_application_traffic_secret` can be deleted.

## Secure communication
At this point, the handshake is finished. Alice and Bob can now talk securely using AES-GCM 128 bits. From now on, every messages are sent encrypted. AES-GCM nonces are obtained by XORing a 8 bytes counter to the last 8 bytes of the IV. The counter is specific to the IV. It's initialized to 0 and incremented by 1 with each use. Here is a python implementation of this nonce generation:
```python
def iv_to_nonce(iv, counter):
    counter_bytes = b"\x00"*4 + counter.to_bytes(8, byteorder="big")
    return bytes([i ^ j for i, j in zip(iv, counter_bytes)])
```

If Alice wants to obfuscate the lengths of her message, she can use PSEC padding on the plain text: she first encodes the real length of her message (4 bytes, big endian) and prefix it to the plain text. She does this so that Bob is able to distinguish the real plain text from the padding. Then, she will append random padding until the total length reach 1000 bytes. If this value is lower than the plain text length, it's multiplied by 2 until the plain text can fit. Here is a python implementation of this padding algorithm:
```python
plain_text = b"Hello Bob !"
encoded_plain_text_length = len(plain_text).to_bytes(4, byteorder="big")

padded_length = 1000
while padded_length < len(encoded_plain_text_length) + len(plain_text):
    padded_length = padded_length * 2

padding_length = padded_length - len(encoded_plain_text_length) - len(plain_text)
padded_message = encoded_plain_text_length + plain_text + os.urandom(padding_length)
```

This padding process is optional. If Alice has a limited bandwidth, she can decide not to pad her messages. In this case, she will just prepend the encoded message length to the plain text so that Bob can use the same algorithm to decode her messages.

| encoded real length | real message |     random padding     |
|:-------------------:|:------------:|:----------------------:|
|       4 bytes       |    X bytes   | `padding_length` bytes |

Once the plain text is ready to be sent, Alice encrypts it with her `local_application_key`. The AES GCM nonce is computed from `local_application_iv` in the way described above. Alice add the cipher text length (including GCM tag) as an additional associated data (AAD) to the AES GCM encrypt function (encoded to 4 bytes in big endian). Therefore, message lengths are authenticated and cannot be tampered. \
_Note: due to this 4 bytes length, messages cannot be larger than 4 294 967 295 bytes (≈4GB)_.
```python
GCM_TAG_LENGTH = 16
encoded_length = (len(padded_message)+GCM_TAG_LENGTH).to_bytes(4, byteorder="big")
nonce = iv_to_nonce(local_counter)
local_counter += 1
cipher_text = AES_128_GCM.encrypt(
    key=local_application_key,
    nonce=nonce,
    plain_text=padded_message,
    aad=encoded_length
)
```
| encoded length |      cipher text      | AES GCM tag |
|:--------------:|:---------------------:|:-----------:|
|     4 bytes    | `padded_length` bytes |   16 bytes  |

When Alice receives a message, she reads the first 4 bytes to get the message length and waits for the exact amout of bytes to be received. Then she decrypts the message with her `peer_application_key` and verifies its authenticity (length and content).
```python
nonce = iv_to_nonce(peer_counter)
peer_counter += 1
padded_plain_text = AES_128_GCM.decrypt(
    key=peer_application_key,
    nonce=nonce,
    cipher_text=received_cipher_text,
    aad=received_message_length
)
```
Then, Alice reads the first 4 bytes of the padded plain text to get the actual length of the real plain text. Thus, she just has to read the first N bytes of the padded plain text and discard the remaining bytes (there are no remaining bytes if Bob didn't use padding). An implementation of this unpadding process in python:
```python
real_encoded_length = padded_plain_text[:4]
real_length = int.from_bytes(real_encoded_length, byteorder="big")
unpadded_plain_text = padded_plain_text[4:4+real_length]
```

# Conclusion
AFAIK, the PSEC protocol provide all expected properties described earlier:
- Peers authentication is insured by ECDHE exchange and Ed25519 signatures with peers' long term identity keys.
- Messages encryption and authentication are insured by AES-GCM.
- Plaintext lengths can be obfuscated using padding.
- Since all parties have the necessary keys to create any arbitrary messages, all sent messages can be denied.
- As far as the communications are ephemeral, forward secrecy is insured: encryption keys are derived from ephemeral keys `ephK`.
- If the ephemeral keys `ephK` are generated using a strong cryptographically secure PRNG, future secrecy is insured.