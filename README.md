# Safe OpenCL Vanity Miner

用 NVIDIA GPU 搜索具有重复十六进制前缀或后缀的 Safe 合约钱包地址。地址通过 Safe Proxy Factory 的 `createProxyWithNonce` 和 CREATE2 派生，不生成或保存私钥。

## 特性

- OpenCL 双重 Keccak-256 计算
- 任意重复字符，前缀和后缀均可
- GPU 搜索结果由 CPU 重新计算 salt、地址和重复位数后才保存
- 包含并行哈希及完整挖矿回归测试

## 环境

- NVIDIA GPU 及驱动
- NVIDIA OpenCL ICD
- Python 3.9+

安装 Python 依赖：

```bash
python3 -m pip install -r requirements.txt
```

Ubuntu 如果提示 `PLATFORM_NOT_FOUND_KHR`，安装 OpenCL loader，并确保 `/etc/OpenCL/vendors/nvidia.icd` 包含 `libnvidia-opencl.so.1`。

## 使用

```bash
python3 safe_miner.py FACTORY INITIALIZER_HASH PROXY_CREATION_CODE_HASH --seconds 3600
```

参数均为不带 `0x` 的 hex。可选参数：

- `--seconds 0`：一直运行，直到 Ctrl+C
- `--work-size`：每次内核启动搜索的 nonce 数，默认 `2^26`
- `--min-score`：GPU 上报候选的最低分数，默认 5
- `--device N`：按序号选择 OpenCL 设备（所有平台合并编号）；默认优先 NVIDIA GPU，其次任意 GPU
- `--output`：结果文件，默认 `best-safe.json`

最佳结果写入 `best-safe.json`，包含：

```json
{
  "score": 11,
  "saltNonce": "8087313955986017249",
  "address": "0x39e232a22c783acf5af79c4e255fd88888888888"
}
```

### 当前 Safe v1.4.1 示例

`initializer.txt` 对应一个 owner、threshold 为 1 的 Safe 设置。运行：

```bash
INITIALIZER_HASH=$(python3 -c 'from Crypto.Hash import keccak; h=keccak.new(digest_bits=256); h.update(bytes.fromhex(open("initializer.txt").read().strip()[2:])); print(h.hexdigest())')
python3 safe_miner.py \
  4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67 \
  "$INITIALIZER_HASH" \
  76733d705f71b79841c0ee960a0ca880f779cde7ef446c989e6d23efc0a4adfb \
  --seconds 3600
```

部署时调用 Factory `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` 的 `createProxyWithNonce`：

- `_singleton`: `0x41675C099F32341bf84BFc5382aF534df5C7461a`
- `initializer`: `initializer.txt` 中完整的一行
- `saltNonce`: 搜索结果中的值

必须保持 initializer 完全一致。修改 owner、threshold 或任何其他初始化参数后，需要重新计算 initializer hash 并重新挖矿。

## 测试

普通单元测试：

```bash
python3 -m unittest -v test_safe_miner
```

GPU 回归测试：

```bash
OPENCL_TEST=1 INITIALIZER_HASH=你的_initializer_hash python3 -m unittest -v test_safe_miner
```

可用 `START_NONCE` 指定并行哈希测试的起始 nonce。GPU 测试会短暂运行完整挖矿，并写入 `best-safe.json`。

## 实现要点

- initializer hash、factory、proxy creation code hash 在主机端预先拼成 Keccak lane，以 `#define` 编译期常量注入内核，Keccak 状态全程使用 64 位 lane 并保留在寄存器中
- 重复位数用 XOR 与 `clz` 计算，不逐个 nibble 比较
- 分数达到阈值（`max(--min-score, 当前最佳 + 1)`）的候选通过 `atomic_inc` 追加到候选缓冲区，无全局锁；主机端每批只读回一个计数器

## 性能参考

优化前的内核实测约为（当前版本请以本机实测为准）：

- RTX 4090：2.4 GH/s
- RTX 5090：3.2 GH/s

每增加一个指定十六进制字符，平均工作量增加 16 倍。速度随驱动、GPU 和实现变化，应以本机实测为准。

## 安全说明

先在主网 fork 或测试网验证部署，再发送真实交易。不要把 API Key、SSH 私钥或钱包私钥提交到仓库。本程序只计算 CREATE2 参数，不会主动发送主网交易。
