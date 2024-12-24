# 基于 SM2 的秘密共享

本项目实现了基于 `sm2` 国密算法库的秘密共享方案，包括 **Shamir 秘密共享 (Secret Sharing)**、**Feldman 可验证秘密共享 (Verifiable Secret Sharing, VSS)** 和 **Pedersen 可验证秘密共享 (VSS)**。项目包含以下功能：

- 基于有限域的多项式生成
- 使用拉格朗日插值进行秘密共享和重建
- 使用 Feldman 和 Pedersen 方案的可验证秘密共享

## 使用方法

运行项目：

```bash
cargo run
```

运行测试：

```bash
cargo test
```

## 模块

### `polynomial`

此模块提供了有限域上多项式运算的功能，包括创建多项式、在特定点求值，以及生成多项式系数的 Feldman 承诺和 Pedersen 承诺。

### `secret_sharing`

此模块实现了 Shamir 秘密共享、Feldman VSS 和 Pedersen VSS 的核心逻辑，支持从秘密生成份额、从份额重建秘密，以及使用承诺验证份额。

## 依赖

- `sm2`: 用于有限域运算和椭圆曲线操作，实现了中国国家密码管理局 (OSCCA) 发布的 SM2 椭圆曲线公钥密码算法。
- `rand`: 用于安全的随机数生成。

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件。