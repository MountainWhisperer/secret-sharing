use sm2::Scalar;
use sm2::elliptic_curve::ff::Field;
use sm2::ProjectivePoint;
use rand::Rng;

/// 表示有限域上的多项式
pub struct Polynomial {
    // 多项式的系数，按照次数从低到高排列
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// 创建一个随机多项式，最高次项为'degree'，常数项为'secret'
    ///
    /// # Arguments
    ///
    /// * `secret` - 多项式的常数项
    /// * `degree` - 多项式的最高次数
    /// * `rng` - 随机数生成器
    pub fn new<R: Rng>(secret: Scalar, degree: usize, rng: &mut R) -> Self {
        // 初始化系数向量，第一个元素为常数项
        let mut coefficients = vec![secret];
        // 生成 degree 个随机系数
        for _ in 0..degree {
            coefficients.push(Scalar::random(&mut *rng));
        }
        // 返回构造的多项式
        Polynomial { coefficients }
    }

    /// 计算多项式在给定 x 处的值
    ///
    /// # Arguments
    ///
    /// * `x` - 自变量的值
    ///
    /// # Returns
    ///
    /// * 多项式在 x 处的值
    pub fn evaluate(&self, x: Scalar) -> Scalar {
        // 使用霍纳法则 (Horner's method) 从高次项到低次项计算多项式的值
        self.coefficients.iter().rev().fold(Scalar::ZERO, |acc, coeff| {
            acc * x + coeff
        })
    }

    /// 生成多项式系数的Pedersen承诺
    ///
    /// # Arguments
    /// * `g` - 公共生成元 g
    /// * `h` - 公共生成元 h
    /// * `rng` - 随机数生成器
    ///
    /// # Returns
    /// * `(Vec<ProjectivePoint>, Polynomial)` - 包含承诺列表和 blinding 因子的多项式
    pub fn commit<R: Rng>(
        &self,
        g: ProjectivePoint,
        h: ProjectivePoint,
        rng: &mut R,
    ) -> (Vec<ProjectivePoint>, Polynomial) {
        let mut commitments = Vec::new();
        let mut blinding_factors = Vec::new();

        for coeff in &self.coefficients {
            let r = Scalar::random(&mut *rng);
            blinding_factors.push(r);

            // 计算 g^coeff 和 h^r
            let commitment = g * *coeff + h * r;
            commitments.push(commitment);
        }

        // 创建 blinding factors 多项式
        let blinding_poly = Polynomial {
            coefficients: blinding_factors,
        };

        (commitments, blinding_poly)
    }

    /// 返回多项式的系数
    pub fn coefficients(&self) -> &Vec<Scalar> {
        &self.coefficients
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use sm2::elliptic_curve::ff::Field;

    #[test]
    fn test_commitment() {
        let mut rng = thread_rng();
        let g = ProjectivePoint::GENERATOR;
        let h = ProjectivePoint::GENERATOR * Scalar::random(&mut rng);

        let secret = Scalar::from(7u64);
        let degree = 2;
        let poly = Polynomial::new(secret, degree, &mut rng);

        let (commitments, _) = poly.commit(g, h, &mut rng);
        assert_eq!(commitments.len(), poly.coefficients.len());

        let (commitments_2, _) = poly.commit(g, h, &mut rng);
        assert_ne!(commitments, commitments_2);
    }

    #[test]
    fn test_commitment_with_random_degree() {
        let mut rng = thread_rng();
        let g = ProjectivePoint::GENERATOR;
        let h = ProjectivePoint::GENERATOR * Scalar::random(&mut rng);

        // 随机生成多项式阶数
        let max_degree = 10;  // 最大多项式阶数
        let num_tests = 100;  // 测试次数

        for _ in 0..num_tests {
            // 随机选择多项式阶数 (1 到 max_degree)
            let degree = rng.gen_range(1..=max_degree);
            let secret = Scalar::from(rng.gen_range(1..100u64));  // 随机选择秘密值

            // 生成多项式
            let poly = Polynomial::new(secret, degree, &mut rng);

            // 生成多项式系数的 Pedersen 承诺和 blinding 多项式
            let (commitments, blinding_poly) = poly.commit(g, h, &mut rng);

            // 随机生成多个 x 点进行验证
            let num_points = 20;  // 每个多项式测试 20 个随机点
            for _ in 0..num_points {
                let x = Scalar::random(&mut rng);  // 随机生成 x

                // 评估多项式和 blinding 多项式在 x 处的值
                let poly_value_at_x = poly.evaluate(x);
                let blinding_value_at_x = blinding_poly.evaluate(x);

                // 直接计算的期望承诺值 g^(poly(x)) * h^(blind(x))
                let expected_commitment = g * poly_value_at_x + h * blinding_value_at_x;

                // 计算承诺的累加值 C_0 + C_1 * x + C_2 * x^2 + ...
                let mut actual_commitment = ProjectivePoint::IDENTITY;
                for (i, commitment) in commitments.iter().enumerate() {
                    actual_commitment += *commitment * x.pow(&[i as u64, 0, 0, 0]);
                }

                // 断言直接计算的承诺和累加计算的承诺是否一致
                assert_eq!(
                    expected_commitment,
                    actual_commitment,
                    "Commitment failed at random x with degree {}!",
                    degree
                );
            }
        }

        println!("All random degree and point tests passed for Pedersen commitment!");
    }
}
