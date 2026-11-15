# mb-attest — 度量启动远程证明验证工具

解析 TCG PC Client **crypto-agile** 度量启动事件日志，按哈希算法分 bank 重放
extend 计算出每个 PCR 的期望值，与 TPM quote 比对；quote 签名用 AK 公钥验证，
nonce 防重放；最后对照可信基线定位导致不一致的具体事件。

## 验证链

```
事件日志 ──parse──> 事件序列 ──replay(PCR = Hash(PCR‖digest))──> 期望 PCR 值
                                                                   │
TPM quote (TPMS_ATTEST) ──┐                                        │
  ├─ extraData == nonce?（防重放，常数时间比较）                      │
  ├─ AK 公钥验签（RSA RSASSA-PKCS1v15 / ECDSA P-256）                │
  └─ pcrDigest == Hash(拼接选中PCR)? <───────────────────────────────┘
                                                                   │
可信基线 (baseline.json) ──> 最终 PCR 比对 + 逐事件走查 ──> 定位首个分歧事件
```

- 日志 ↔ quote 一致：证明日志忠实反映了 TPM 当前状态（日志没被掉包）。
- 日志 ↔ 基线一致：证明系统实际启动的是受信任的组件。
- 两层分开：quote 对得上但基线对不上 = 系统被换过（如固件/内核被改）；
  quote 对不上 = 日志本身不可信。

## 用法

```bash
# 生成测试数据（事件日志、RSA/ECDSA 两套 quote、AK 公钥、基线、nonce）
cargo run --bin gen_fixtures -- --out fixtures

# 看懂一份事件日志
cargo run --bin mb-attest -- show-log --log fixtures/eventlog.bin

# 只重放，看各 bank 的 PCR 期望值
cargo run --bin mb-attest -- replay --log fixtures/eventlog.bin [--alg sha256]

# 完整验证（nonce 为 hex，或用 @file 从文件读）
cargo run --bin mb-attest -- verify \
  --log fixtures/eventlog.bin \
  --quote fixtures/quote-rsa.bin \
  --sig fixtures/quote-rsa.bin.sig \
  --ak fixtures/ak-rsa.pem \
  --nonce $(cat fixtures/nonce.hex) \
  --baseline fixtures/baseline.json
# 退出码 0 = ATTESTED，1 = REJECTED，2 = 用法/IO 错误
```

真实环境对接：`--log` 用 `/sys/kernel/security/tpm0/binary_bios_measurements`，
`--quote`/`--sig` 用 `tpm2_quote` 输出的 TPMS_ATTEST 与签名（RSA 原始签名；
ECDSA 支持 64 字节 r‖s 或 DER），`--ak` 为 SPKI PEM 公钥。

## 支持的格式

- **事件日志**：Spec ID Event03 头 + `TCG_PCR_EVENT2` 记录（小端）。哈希 bank：
  sha1 / sha256 / sha384 / sha512。legacy SHA-1-only 格式会明确报错。
- **quote**：`TPMS_ATTEST`（大端），接受裸结构或带 2 字节长度头的 `TPM2B_ATTEST`；
  校验 magic `0xFF544347`、类型 `TPM_ST_ATTEST_QUOTE (0x8018)`。
- **AK**：RSA（RSASSA-PKCS1v15，签名哈希可用 `--sig-hash` 指定）与 ECDSA P-256。

## 可信基线格式（baseline.json，version 1)

```json
{
  "version": 1,
  "name": "ubuntu-24.04-golden",
  "events": [
    {
      "pcr": 0,
      "event_type": "EV_S_CRTM_CONTENTS",
      "digests": { "sha256": "fd4c0d83…", "sha1": "9a457f95…" },
      "description": "Core Root of Trust for Measurement"
    }
  ],
  "pcrs": {
    "sha256": { "0": "5b0b2535…", "7": "…" }
  }
}
```

- `events`：按日志顺序列出所有应被 extend 的事件（不含 EV_NO_ACTION）。
  验证时与日志逐事件走查，**首个 digest 不同 / 多出 / 缺失的事件**即为分歧点。
- `pcrs`：各 bank 最终 PCR 期望值，可只列子集；用于快速判定哪个 PCR 不一致。
  与 `events` 冗余是有意的——没有逐事件数据时也能做最终值校验。

## 测试

`cargo test` 覆盖：RSA/ECDSA 正常证明、nonce 错误、签名篡改、日志被篡改
（与 quote 不符）、系统变更（与基线不符并定位到 PCR 9 的 EV_IPL 事件）、
TPM2B 包装兼容、legacy 日志拒绝。测试日志与 quote 由 `src/fixture.rs`
按 TCG/TPM2 规范手工序列化构造，与解析器互为交叉验证。
