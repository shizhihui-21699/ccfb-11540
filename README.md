# tpm-ra-verify

一个用 Rust 实现的 TCG 度量启动（Measured Boot）远程证明验证工具。它能：

1. **解析 TCG 事件日志** —— 同时支持 crypto-agile（`TCG_PCR_EVENT2`，含
   SHA-1/SHA-256/SHA-384/SHA-512 多算法 bank）和 legacy SHA-1（`TCG_PCR_EVENT`）
   两种线格式；
2. **按算法重放 PCR** —— 对每个事件、每个算法独立执行
   `PCR_new = Hash(PCR_old || digest)`，算出 24 个 PCR 的期望值；
3. **验证 TPM Quote** —— 解析 `TPMS_ATTEST` / `TPMT_SIGNATURE` /
   `TPMT_PUBLIC`，用 AK 公钥校验签名（RSASSA 与 ECDSA-P256），重算 quote 中的
   PCR 复合摘要并逐 PCR 比对；
4. **Nonce 防重放** —— quote 携带的 nonce 必须等于验证方下发的挑战值，且
   已接受过的 nonce 持久化记录、绝不接受第二次；
5. **对照可信基线定位分歧事件** —— 逐事件（PCR 编号、事件类型、各算法摘要、
   事件数据）比较，明确指出是**第几个事件**导致 PCR 不一致，并给出最终 PCR
   层面的差异。

所有密码学运算均使用 RustCrypto 维护的 `sha1` / `sha2` / `rsa` / `p256` 实现。

## 目录结构

```
src/
  codec.rs        大端字节读写器（TCG/TPM 共用，错误带绝对字节偏移）
  tcg.rs          TCG/TPM 常量、事件类型名、算法摘要长度表
  eventlog.rs     TCG 事件日志解析器 + 线格式构造器（供样本生成）
  replay.rs       分算法 PCR 重放
  tpm.rs          TPMS_ATTEST/TPMT_SIGNATURE/TPMT_PUBLIC 解析、AK 签名验证、
                  PCR 复合摘要重算、PEM/TPM2B 公钥加载
  tpm_builder.rs  符合规范的合成 AK / quote 构造（样本与测试用）
  nonce.rs        nonce 新鲜度检查 + 落盘防重放缓存
  baseline.rs     基线 JSON 格式、逐事件/逐 PCR 差异分析
  verify.rs       端到端编排
  samples.rs      确定性样本构造（黄金日志、篡改日志、legacy 日志、quote）
  main.rs         CLI（parse / replay / baseline / verify）
  bin/gen-samples.rs  样本生成器
tests/integration.rs 22 个端到端测试
```

## 快速开始

```bash
# 1. 生成全套确定性样本（日志、AK、quote、基线）
cargo run --bin gen-samples

# 2. 看懂事件日志
cargo run --bin tpm-ra-verify -- parse samples/golden.log

# 3. 重放 PCR（三个算法 bank 各 24 个）
cargo run --bin tpm-ra-verify -- replay samples/golden.log

# 4. 完整远程证明验证（签名 + nonce + PCR + 基线）
cargo run --bin tpm-ra-verify -- verify \
    samples/golden.log \
    samples/quote-rsa-sha256.quote \
    --nonce @samples/nonce.txt \
    --baseline samples/baseline.json \
    --nonce-cache /var/lib/ra/nonces.json
```

验证通过时退出码为 `0`；任一检查失败为 `1`；结构性错误（文件损坏、格式非法）
为 `2`。加 `--json` 可输出机器可读结果。

### Nonce 的三种传参方式

| 写法 | 含义 |
| --- | --- |
| `--nonce @path/to/file` | 读取文件原始字节作为 nonce |
| `--nonce 0x616263...` | 十六进制解码 |
| `--nonce any-ascii-text` | 直接作为 ASCII 字节（长度 ≥16 的纯 hex 串会按 hex 解码） |

真实部署中，验证方应先通过带外通道生成加密随机的挑战 nonce，再要求被证明方
让 TPM 把该 nonce 放进 `TPM2_Quote` 的 `qualifyingData`。

## 验证逻辑（verify 的检查顺序）

1. 解析事件日志 → 分算法重放全部 PCR；
2. 解析 quote bundle，可选地用外部 AK 文件（TPM2B_PUBLIC 或 PEM）核对
   bundle 内嵌 AK 是否为同一把密钥；
3. **nonce 新鲜度**：与期望挑战值不同 → `NonceMismatch`；命中历史缓存 →
   `ReplayedNonce`。此步失败直接终止，后续检查无意义；
4. **AK 签名**：对完整 `TPM2B_ATTEST`（u16 长度前缀 + 载荷）验证
   RSASSA-PKCS#1-v1.5 或 ECDSA，签名哈希由签名结构里的 `hashAlg` 决定，
   并与 AK 对象上固定的 scheme hash 做一致性检查；
5. **PCR 复合摘要**：按 quote 的 `TPML_PCR_SELECTION` 序列化选择位图，拼接
   各 PCR 重放值后哈希，与 `pcrDigest` 比较；
6. **基线比对**（可选）；
7. 全部通过后，才把本次 nonce 原子写入缓存文件（临时文件 + rename）。

## 基线文件格式（本工具设计）

版本化 JSON（`schema_version: 1`），由 `baseline` 子命令从一条**已被人工或
带外流程确认可信**的黄金日志生成：

```json
{
  "schema_version": 1,
  "created_at": "2026-11-17T00:00:00Z",
  "description": "golden synthetic measured-boot chain (PCR0..9)",
  "log_format": "crypto-agile",
  "algorithms": [
    { "algorithm": 11, "name": "sha256", "digest_size": 32 }
  ],
  "pcr_banks": {
    "sha256": { "0": "1ffe081f…", "9": "172b4168…" }
  },
  "events": [
    {
      "sequence": 22,
      "pcr": 9,
      "event_type": 13,
      "event_type_name": "EV_IPL",
      "digests": { "sha256": "9345c3e2…" },
      "event_data": "636f6e736f6c65…",
      "extends_pcr": true
    }
  ]
}
```

设计要点：

* **逐事件快照 + 最终 PCR 双视图**。事件级字段用于回答“谁导致的”，PCR 级
  字段用于独立交叉核对重放结果；
* 比较是**按位置（sequence）**进行的——度量顺序本身就是信任链的一部分，
  调换两个事件顺序也会被检出；
* `event_data` 以 hex 存储，避免二进制 UEFI 变量数据破坏 JSON；
* 支持双向差异：摘要被改、摘要缺失、出现基线外的多余摘要、事件多出/缺失、
  PCR 编号变化、事件类型变化、事件数据变化、extend 标志变化。

篡改样本（向内核命令行注入 `init=/bin/evil`）的实际定位输出：

```
DIVERGENCE: event #22 sha256 digest differs: observed 340cc578… baseline 9345c3e2…
DIVERGENCE: event #22 event data differs: observed 636f6e736f6c65…2f62696e2f6576696c baseline 636f6e736f6c65…
PCR DIVERGENCE: sha256 PCR9 observed 61817e86… baseline 172b4168…
```

`observed` 事件数据末尾的 hex 解码即 `init=/bin/evil`。

## 合成样本说明

`gen-samples` 生成的材料按 TCG PC Client Firmware Profile 与 TPM 2.0 Part 2
的真实线格式构造，**不是**简化的测试桩：

* 日志以 Spec ID Event03（16 字节 NUL 填充签名、platformClass、算法表）开头，
  随后是 StartupLocality 事件，再是覆盖 PCR 0/1/2/4/5/7/9 的 CRTM → UEFI
  变量 → GPT → shim/grub → ExitBootServices → 内核命令行/内核镜像事件链；
* 事件摘要是对事件数据的**真实哈希**，因此重放走的是真实密码路径；
* quote 是真实签名的 `TPMS_ATTEST`（magic `0xFF54`、type `0x8018`、clock、
  firmwareVersion、PCR 选择位图、pcrDigest、nonce），RSA-2048/RSASSA 与
  NIST P-256/ECDSA 各一份；
* 另附三个负样本：坏签名 quote、错误 nonce quote、篡改日志。

样本由固定 RNG 种子生成，产物字节稳定，可直接用于回归测试。**这些是教学/
测试材料，不包含也不代表任何真实设备的 AK。**

## 支持范围与边界

| 能力 | 支持情况 |
| --- | --- |
| 日志格式 | crypto-agile `TCG_PCR_EVENT2`、legacy `TCG_PCR_EVENT` |
| 哈希算法 | SHA-1（仅重放/解析）、SHA-256、SHA-384、SHA-512 |
| AK 签名 | RSASSA-PKCS#1-v1.5（SHA-256/384/512）、ECDSA P-256（SHA-256/384/512，prehash 验证） |
| AK 封装 | TPM2B_PUBLIC、PEM SubjectPublicKeyInfo（RSA / P-256） |
| PCR | 0..=23（PC Client 动态/静态 PCR；24+ 的 TPM 最大索引会报错） |
| 防重放 | nonce 等值校验 + 持久化一次性缓存 |

刻意不支持：RSASSA-PSS / ECDAA / 对称 HMAC 方案、SHA-1 签名验证（SHA-1
签名已被 TCG 规范弃用，解析仍可识别但拒绝验证）、TPM 之外的事件日志签名。

## 测试

```bash
cargo test       # 22 个集成测试：解析、重放、签名、nonce、PCR 分歧、基线定位
cargo clippy --all-targets   # 零警告
```

测试覆盖的关键性质包括：legacy 与 agile 日志对同一 SHA-1 事件链重放出
**完全相同**的 PCR 值、篡改事件只改变其下游 PCR、同一 nonce 第二次提交被
拒绝、损坏签名/错误 magic/越界 PCR/截断日志均被带偏移地拒绝。
