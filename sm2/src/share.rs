use sm2::Scalar;
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
