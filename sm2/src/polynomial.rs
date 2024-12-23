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

    /// 生成多项式系数的 Feldman 承诺
    ///
    /// # Arguments
    ///
    /// * `g` - 公共生成元
    ///
    /// # Returns
    ///
    /// * `Vec<ProjectivePoint>` - 包含承诺的列表
    pub fn feldman_commit(&self, g: ProjectivePoint) -> Vec<ProjectivePoint> {
        let mut commitments = Vec::new();

        for coeff in &self.coefficients {
            // 计算 g^coeff
            let commitment = g * *coeff;
            commitments.push(commitment);
        }

        commitments
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
    pub fn pedersen_commit<R: Rng>(
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
