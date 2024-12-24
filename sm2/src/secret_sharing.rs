use sm2::elliptic_curve::ff::Field;
use sm2::{ProjectivePoint, Scalar};
use rand::Rng;
use crate::polynomial::Polynomial;

/// 生成 n 个份额，至少需要 t 个份额才能恢复秘密
pub fn generate_shares<R: Rng>(secret: Scalar, n: usize, t: usize, rng: &mut R) -> Vec<(Scalar, Scalar)> {
    // 创建一个 t-1 次的随机多项式，其常数项为秘密值
    let poly = Polynomial::new(secret, t - 1, rng);
    // 生成 n 个份额，每个份额是一个 (x, y) 对
    (1..=n).map(|i| {
        // x 坐标为 1 到 n 的整数
        let x = Scalar::from(i as u64);
        // y 坐标为多项式在 x 处的值
        let y = poly.evaluate(x);
        // 返回 (x, y) 对
        (x, y)
    }).collect()
}

/// 使用拉格朗日插值恢复秘密
pub fn reconstruct_secret(shares: &[(Scalar, Scalar)]) -> Scalar {
    // 初始化秘密为 0
    let mut secret = Scalar::ZERO;
    // 遍历每个份额
    for (i, &(x_i, y_i)) in shares.iter().enumerate() {
        // 初始化分子和分母为 1
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        // 遍历其他份额，计算拉格朗日插值多项式的系数
        for (j, &(x_j, _)) in shares.iter().enumerate() {
            // 如果是同一个份额，则跳过
            if i != j {
                // 分子乘以 x_j
                numerator *= x_j;
                // 分母乘以 (x_j - x_i)
                denominator *= x_j - x_i;
            }
        }
        // 计算拉格朗日系数
        let lagrange_coefficient = numerator * denominator.invert().unwrap();
        // 将 y_i 乘以拉格朗日系数并累加到秘密中
        secret += y_i * lagrange_coefficient;
    }
    // 返回重建的秘密
    secret
}

/// 采用 Feldman 可验证秘密共享方案生成 n 个份额，至少需要 t 个份额才能恢复秘密，并返回份额和对应的承诺
///
/// # Arguments
///
/// * `secret` - 要分享的秘密
/// * `n` - 份额的总数
/// * `t` - 恢复秘密所需的最小份额数
/// * `g` - 生成元
/// * `rng` - 随机数生成器
///
/// # Returns
///
/// * `(Vec<(Scalar, Scalar)>, Vec<ProjectivePoint>)` - 包含份额的列表和对应的 Feldman 承诺列表
pub fn generate_shares_with_feldman_vss<R: Rng>(
    secret: Scalar,
    n: usize,
    t: usize,
    g: ProjectivePoint,
    rng: &mut R,
) -> (Vec<(Scalar, Scalar)>, Vec<ProjectivePoint>) {
    // 创建一个 t-1 次的随机多项式，其常数项为秘密值
    let poly = Polynomial::new(secret, t - 1, rng);
    // 生成多项式系数的 Feldman 承诺
    let commitments = poly.feldman_commit(g);

    // 生成 n 个份额，每个份额是一个 (x, y) 对
    let shares = (1..=n)
        .map(|i| {
            // x 坐标为 1 到 n 的整数
            let x = Scalar::from(i as u64);
            // y 坐标为多项式在 x 处的值
            let y = poly.evaluate(x);
            // 返回 (x, y) 对
            (x, y)
        })
        .collect();

    // 返回份额和对应的承诺
    (shares, commitments)
}

/// 使用 Feldman 承诺验证份额的有效性
///
/// # Arguments
///
/// * `share` - 要验证的份额 (x, y)
/// * `commitments` - Feldman 承诺列表
/// * `g` - 生成元
///
/// # Returns
///
/// * `bool` - 如果份额有效，则返回 true；否则返回 false
pub fn verify_share_with_feldman_vss(
    share: (Scalar, Scalar),
    commitments: &[ProjectivePoint],
    g: ProjectivePoint,
) -> bool {
    let (x, y) = share;

    // 计算 g^y
    let g_to_y = g * y;

    // 计算承诺的累加值 C_0 + C_1 * x + C_2 * x^2 + ...
    let mut commitment_at_x = ProjectivePoint::IDENTITY;
    for (i, commitment) in commitments.iter().enumerate() {
        commitment_at_x += *commitment * x.pow(&[i as u64, 0, 0, 0]);
    }

    // 验证 g^y 是否等于承诺的累加值
    g_to_y == commitment_at_x
}

/// 采用 Pedersen 可验证秘密共享方案生成 n 个份额，至少需要 t 个份额才能恢复秘密，并返回份额、对应的承诺以及致盲多项式
///
/// # Arguments
///
/// * `secret` - 要分享的秘密
/// * `n` - 份额的总数
/// * `t` - 恢复秘密所需的最小份额数
/// * `g` - 生成元 g
/// * `h` - 生成元 h
/// * `rng` - 随机数生成器
///
/// # Returns
///
/// * `(Vec<(Scalar, Scalar)>, Vec<ProjectivePoint>, Polynomial)` - 包含份额的列表、对应的 Pedersen 承诺列表以及盲化多项式
pub fn generate_shares_with_pedersen_vss<R: Rng>(
    secret: Scalar,
    n: usize,
    t: usize,
    g: ProjectivePoint,
    h: ProjectivePoint,
    rng: &mut R,
) -> (Vec<(Scalar, Scalar)>, Vec<ProjectivePoint>, Polynomial) {
    // 创建一个 t-1 次的随机多项式，其常数项为秘密值
    let poly = Polynomial::new(secret, t - 1, rng);
    // 生成多项式系数的 Pedersen 承诺和盲化多项式
    let (commitments, blinding_poly) = poly.pedersen_commit(g, h, rng);

    // 生成 n 个份额，每个份额是一个 (x, y) 对
    let shares = (1..=n)
        .map(|i| {
            // x 坐标为 1 到 n 的整数
            let x = Scalar::from(i as u64);
            // y 坐标为多项式在 x 处的值
            let y = poly.evaluate(x);
            // 返回 (x, y) 对
            (x, y)
        })
        .collect();

    // 返回份额、对应的承诺以及盲化多项式
    (shares, commitments, blinding_poly)
}

/// 使用 Pedersen 承诺验证份额的有效性
///
/// # Arguments
///
/// * `share` - 要验证的份额 (x, y)
/// * `commitments` - Pedersen 承诺列表
/// * `blinding_poly` - 盲化多项式
/// * `g` - 生成元 g
/// * `h` - 生成元 h
///
/// # Returns
///
/// * `bool` - 如果份额有效，则返回 true；否则返回 false
pub fn verify_share_with_pedersen_vss(
    share: (Scalar, Scalar),
    commitments: &[ProjectivePoint],
    blinding_poly: &Polynomial,
    g: ProjectivePoint,
    h: ProjectivePoint,
) -> bool {
    let (x, y) = share;

    // 计算 g^y
    let g_to_y = g * y;

    // 计算 h^(blinding_poly(x))
    let h_to_blinding_at_x = h * blinding_poly.evaluate(x);

    // 计算承诺的累加值 C_0 + C_1 * x + C_2 * x^2 + ...
    let mut commitment_at_x = ProjectivePoint::IDENTITY;
    for (i, commitment) in commitments.iter().enumerate() {
        commitment_at_x += *commitment * x.pow(&[i as u64, 0, 0, 0]);
    }

    // 验证 g^y * h^(blinding_poly(x)) 是否等于承诺的累加值
    g_to_y + h_to_blinding_at_x == commitment_at_x
}