use sm2::elliptic_curve::ff::Field;
use sm2::{ProjectivePoint, Scalar, elliptic_curve::group::Group};
use shamir_secret_sharing::polynomial::Polynomial;
use rand::Rng;

#[test]
fn test_pedersen_commitment() {
    let mut rng = rand::thread_rng();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::random(&mut rng);

    let secret = Scalar::from(7u64);
    let degree = 2;
    let poly = Polynomial::new(secret, degree, &mut rng);

    let (commitments, _) = poly.pedersen_commit(g, h, &mut rng);
    assert_eq!(commitments.len(), poly.coefficients().len());

    let (commitments_2, _) = poly.pedersen_commit(g, h, &mut rng);
    assert_ne!(commitments, commitments_2);
}

#[test]
fn test_pedersen_commitment_with_random_degree() {
    let mut rng = rand::thread_rng();
    let g = ProjectivePoint::GENERATOR;
    let h = ProjectivePoint::random(&mut rng);
    // 随机生成多项式阶数
    let max_degree = 10; // 最大多项式阶数
    let num_tests = 100; // 测试次数

    for _ in 0..num_tests {
        // 随机选择多项式阶数 (1 到 max_degree)
        let degree = rng.gen_range(1..=max_degree);
        let secret = Scalar::from(rng.gen_range(1..100u64)); // 随机选择秘密值

        // 生成多项式
        let poly = Polynomial::new(secret, degree, &mut rng);

        // 生成多项式系数的 Pedersen 承诺和 blinding 多项式
        let (commitments, blinding_poly) = poly.pedersen_commit(g, h, &mut rng);

        // 随机生成多个 x 点进行验证
        let num_points = 20; // 每个多项式测试 20 个随机点
        for _ in 0..num_points {
            let x = Scalar::random(&mut rng); // 随机生成 x

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

#[test]
fn test_feldman_commitment() {
    let mut rng = rand::thread_rng();
    let g = ProjectivePoint::GENERATOR;

    let secret = Scalar::from(7u64);
    let degree = 2;
    let poly = Polynomial::new(secret, degree, &mut rng);

    let commitments = poly.feldman_commit(g);
    assert_eq!(commitments.len(), poly.coefficients().len());

    // 验证承诺
    for (i, commitment) in commitments.iter().enumerate() {
        let expected_commitment = g * poly.coefficients()[i];
        assert_eq!(
            *commitment, expected_commitment,
            "Commitment failed at index {}!",
            i
        );
    }
}

#[test]
fn test_feldman_commitment_with_random_degree() {
    let mut rng = rand::thread_rng();
    let g = ProjectivePoint::GENERATOR;

    // 随机生成多项式阶数
    let max_degree = 10; // 最大多项式阶数
    let num_tests = 100; // 测试次数

    for _ in 0..num_tests {
        // 随机选择多项式阶数 (1 到 max_degree)
        let degree = rng.gen_range(1..=max_degree);
        let secret = Scalar::from(rng.gen_range(1..100u64)); // 随机选择秘密值

        // 生成多项式
        let poly = Polynomial::new(secret, degree, &mut rng);

        // 生成多项式系数的 Feldman 承诺
        let commitments = poly.feldman_commit(g);

        // 随机生成多个 x 点进行验证
        let num_points = 20; // 每个多项式测试 20 个随机点
        for _ in 0..num_points {
            let x = Scalar::random(&mut rng); // 随机生成 x

            // 评估多项式在 x 处的值
            let poly_value_at_x = poly.evaluate(x);

            // 直接计算的期望承诺值 g^(poly(x))
            let expected_commitment = g * poly_value_at_x;

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

    println!("All random degree and point tests passed for Feldman commitment!");
}
