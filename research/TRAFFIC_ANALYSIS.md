# Traffic analysis of pqvpn: threat model, experiment and decision

Status: research note, 2026-10-17. The experiment is reproducible
([traffic_analysis/experiment.py](traffic_analysis/experiment.py)) and its raw results are in
[results/traffic_analysis.json](results/traffic_analysis.json). Everything here concerns the **VPN client and
protocol**. The investigation, OSINT and attribution topics in the research guide are out of scope: this
repository does not implement them and must not. See [Boundaries](#5-boundaries).

## 1. Threat model

**Who observes.** A passive on-path party between the device and the VPN server. Examples: the Wi-Fi operator, the
mobile or home ISP, a national middlebox, or the hosting provider of the server's uplink.

**What pqvpn hides from them.**

* Inner IP addresses, ports and payloads. Everything is AEAD-encrypted.
* DNS queries, provided the server pushes a DNS server inside the tunnel. The Android client now **refuses a full
  tunnel without one**, because the queries would otherwise go to the underlying network.
* Inner packet lengths, but only to 16-byte granularity.

**What they still see.**

| Observable | Detail | Consequence |
| --- | --- | --- |
| Endpoint | Server IP and UDP port (default 51820) | "This device talks to a ShieldsVPN server" |
| Protocol shape | First byte `0x01` (handshake) or `0x04` (data); the version byte `0x01`; handshake messages split into 1216-byte fragments; a data header carrying an in-clear 64-bit counter that increments per packet | Passive protocol identification is easy, comparable to WireGuard. The research guide's summary of *OpenVPN is Open to VPN Fingerprinting* (§9.5) describes exactly this class of byte-pattern and size fingerprinting. pqvpn makes no attempt to look like other traffic. |
| Sizes | 16-byte multiple + 32 bytes per datagram | See the experiment. Barely better than no padding. |
| Timing, direction, volume | Unchanged by the tunnel | The dominant leak. See the experiment. |

**What this enables.** Inferring the *kind* of activity inside the tunnel (calls, video, bulk download, browsing,
typing) and, under closed-world assumptions, the website. The research guide stresses that this is classification
under controlled conditions, not identification of a person (§1 and the caveats under §9.2–9.9). Its summary of
*Seamless Website Fingerprinting in Multiple Environments* (§9.6) emphasises that accuracy depends on environment
and training variability. That motivates the environment-split evaluation below.

> Source note: the research guide's paper **summaries** were used. The underlying papers were not read in full for
> this note, so no number from them is quoted beyond what the guide states.

## 2. Experiment

**Question.** Against a realistic, cheap attacker, how much does each candidate defence reduce the attacker's
ability to tell six activity classes apart, and at what cost?

**Data.**

* *Synthetic* traces from explicit workload models: web, video, voip, bulk, chat and interactive.
* Each trace is a 5 s window of `(time, direction, IP length)`, with 50 traces per class and environment, over 3 seeds.
* No customer traffic, browsing history or packet capture was used or collected.
* The models are simple and are documented in the code. A real-traffic evaluation would need consenting
  volunteers and a lab, not customers.

**Environments.**

| Environment | RTT | Bandwidth | Jitter | Tunnel MTU |
| --- | --- | --- | --- | --- |
| A | 20 ms | 50 Mbit/s | 1 ms | 1420 |
| B | 80 ms | 8 Mbit/s | 4 ms | 1280 |

Models are trained on one environment and tested on the other, in both directions. A same-environment random
split is reported alongside to show how optimistic it is. This follows the guide's §8 recommendation to split
by environment.

**Wire sizes.** Computed with the production `pqvpn.session.pad()` and `DATA_OVERHEAD`. At start-up the script
checks the model against a real `Keypair.encrypt`/`decrypt` for both production AEAD suites: 40 cases, all matching.

**Attacker.**

* kNN (k = 5) and nearest-centroid classifiers.
* 38 standardised features: per-direction counts and bytes, an 8-bin size histogram, size statistics,
  inter-arrival percentiles, burst statistics and per-second variability.
* A deep sequence model would be at least as strong, so a defence that fails against this attacker fails in
  practice.

**Metrics.**

* Macro precision, recall, F1 and FPR.
* Accuracy, which is reported but is not the headline.
* Confusion matrices, which are in the JSON.
* Chance accuracy is 0.167. Constant prediction gives macro-F1 0.048.

**Defences compared.**

| Defence | Wire-compatible with today's servers? |
| --- | --- |
| No padding | Reference only. |
| **pad16** | Today's production behaviour. |
| Bucket padding to 128/256/512/1024/MTU | Yes, sender-side only. |
| Pad every packet to the MTU | Yes, sender-side only. |
| Constant-rate cover at 50/200 pps (up/down) | **Simulation only.** |
| Constant-rate cover at 400/1600 pps (up/down) | **Simulation only.** |

Padding is wire-compatible because the receiver strips padding using the inner IP length. A regression test proves
this end to end with real nodes: `TestEndToEnd.test_receiver_accepts_larger_sender_padding`.

Cover traffic needs a protocol change. A padded empty packet is treated as malformed and dropped, and is not
counted as a keepalive. See §4.

### Results

The first figure in each F1 cell is the mean over 3 seeds; the range follows in brackets. The other columns are
from seed 1. Run on Linux (WSL 2), Python 3.12.3, OpenSSL 3.5.9, in 71 s.

| Defence | kNN macro-F1, cross-env | centroid macro-F1, cross-env | kNN accuracy | kNN macro-FPR | kNN macro-F1, same-env split | kNN F1, size features only | kNN F1, timing/volume only |
| --- | --- | --- | --- | --- | --- | --- | --- |
| none (reference) | 0.704 [0.699–0.707] | 0.785 [0.756–0.812] | 0.752 | 0.050 | 0.987 | 0.978 | 0.537 |
| **pad16 (production)** | 0.712 [0.707–0.715] | 0.806 [0.778–0.822] | 0.762 | 0.048 | 0.987 | 0.978 | 0.541 |
| bucket 128/256/512/1024/MTU | 0.743 [0.737–0.753] | 0.807 [0.796–0.817] | 0.765 | 0.047 | 0.987 | 0.967 | 0.537 |
| pad to MTU | 0.500 [0.489–0.509] | 0.553 [0.542–0.566] | 0.608 | 0.078 | 0.994 | 0.048 | 0.509 |
| constant-rate 50/200 pps (sim.) | 0.048 [0.048–0.048] | 0.048 | 0.167 | 0.167 | 0.051 | 0.048 | 0.048 |
| constant-rate 400/1600 pps (sim.) | 0.048 [0.048–0.048] | 0.048 | 0.167 | 0.167 | 0.051 | 0.048 | 0.048 |

Cost, seed 1 (bytes on the wire relative to pad16):

| Defence | All traffic | web | video | voip | bulk | chat | interactive | Added latency, median / p95 | Real packets not sent within the window |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| none | −0.4 % | −0 % | −0 % | −4 % | −0 % | −1 % | −4 % | 0 / 0 ms | 0 % |
| bucket | +2.5 % | +4 % | +2 % | +36 % | +2 % | +4 % | +26 % | 0 / 0 ms | 0 % |
| pad to MTU | +47.9 % | +50 % | +45 % | +690 % | +45 % | +57 % | +560 % | 0 / 0 ms | 0 % |
| constant 50/200 | −25.5 %\* | +69 % | −61 %\* | +3966 % | −79 %\* | +2011 % | +12075 % | 1178 / 3762 ms | 75.5 % |
| constant 400/1600 | +495 % | +1250 % | +214 % | +32379 % | +65 % | +16764 % | +97148 % | 69 / 1905 ms | 19.3 % |

\* A negative value means the cover rate is below the demand: most real traffic is withheld, not delivered.
The simulation does not cap the cover stream at the link rate. 1600 pps × 1312 B is about 17 Mbit/s, which is more
than environment B's 8 Mbit/s, so the real cost there would be higher still.

### Interpretation

1. **Production pad16 is equivalent to no padding** against this attacker: 0.712 vs 0.704 macro-F1. Its value is
   limited to hiding exact lengths.
2. **Bucket padding does not help.** It slightly *raises* cross-environment F1 (0.743), plausibly because
   quantised sizes are more stable across MTUs. It is not worth shipping.
3. **Sizes are the most transferable signal.** Size features alone reach 0.978, above all features combined.
   Timing and volume features shift between environments and hurt kNN's transfer. Removing the size channel
   entirely (pad to MTU) brings macro-F1 down to 0.50, but timing and volume alone still give about 0.51. That
   costs 48 % more bytes overall, and 6–8× for VoIP and interactive traffic, which is mobile data and battery.
4. **Only shaping timing and volume reaches chance,** and at these rates it either withholds most traffic or
   multiplies the bytes 6× while still adding seconds of latency at p95. That is unacceptable for a general-purpose
   VPN. It would only fit a dedicated "high-risk mode" with adaptive rates, which is a research project in itself.
5. **Same-environment random splits overstate the attack:** 0.987 vs 0.71 cross-environment. Any future evaluation
   that reports only random splits should be treated with caution.

### Decision

**No padding or cover-traffic option is added to the client.** The measured evidence does not support it.
Bucket padding has no benefit. MTU padding costs about 48 % more data, up to 8× for calls, and removes only part
of the signal. Cover traffic would need protocol and server changes, plus a cost model that users understand.
The production packet format, transcript and negotiation are unchanged.

## 3. Limitations

* Synthetic workloads with a 5 s window and six classes in a closed world. Real traffic is more varied, and an open
  world (an unknown class) makes the attacker's job harder and the defender's evaluation different.
* A classical attacker. Deep models on packet sequences would likely score higher on every row. The relative
  ordering of defences is the robust result, not the absolute numbers.
* Two environments. More environments would show whether the cross-environment drop is stable.
* No real-device traces were used. The Android emulator's `-tcpdump` capture did not include the Wi-Fi path, so
  the device-side check was functional (leak probes), not pcap-based.

## 4. Future work that needs protocol or server changes (not done)

* **A protocol-level dummy/padding message.** For example, a data-plane plaintext of zero IP version with an
  explicit "padding" marker, which the receiver counts as liveness and discards silently. This changes the
  receive semantics, so it needs a protocol version bump and negotiation in INIT/RESPONSE (a capability bit) for
  compatibility with deployed servers.
* **Server-side shaping for the download direction.** Most bytes flow down, and a client-only defence cannot
  shape them.
* **Reducing protocol fingerprintability:** for example, encrypting the data header counter as QUIC does with
  header protection, and less regular handshake fragment sizes. This is a versioned wire-format change and must
  not be done silently.

## 5. Boundaries

* The VPN client collects no browsing history, packet captures or browser fingerprints, and has no OSINT,
  attribution or surveillance features. The research guide's investigation workflow is for authorized
  incident response on one's own logs. It belongs in separate tooling, if anywhere, and not in this app.
* No claim of anonymity or undetectability is made. pqvpn traffic is identifiable as pqvpn, and the kind of
  activity inside it remains partly inferable, as measured above.

## Reproduce

```sh
PQVPN_LIBCRYPTO=/path/to/libcrypto.so.3 python3 research/traffic_analysis/experiment.py \
    --seeds 1,2,3 --out research/results/traffic_analysis.json      # ~70 s; --quick for ~5 s
```
