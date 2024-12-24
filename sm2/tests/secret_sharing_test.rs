use rand::{rngs::OsRng, Rng, seq::SliceRandom};
use shamir_secret_sharing::secret_sharing::{generate_shares, reconstruct_secret, generate_shares_with_feldman_vss, verify_share_with_feldman_vss,generate_shares_with_pedersen_vss, verify_share_with_pedersen_vss};
use sm2::{ProjectivePoint, Scalar};
use sm2::elliptic_curve::ff::Field;

#[test]
fn test_secret_sharing() {
    // 创建一个随机数生成器
    let mut rng = OsRng;
    // 设置要分享的秘密，这里是一个标量
    let secret = Scalar::random(&mut rng);
    // 设置分享的总数
    let n = 5;
    // 设置恢复秘密所需的最小份额数（门限值）
    let t = 3;

    // 生成秘密分享
    let shares = generate_shares(secret, n, t, &mut rng);
    // 打印生成的分享
    println!("Shares: {:?}", shares);

    // 使用部分份额恢复秘密
    // 从生成的分享中取前t个分享来恢复秘密
    let reconstructed_secret = reconstruct_secret(&shares[0..t]);
    // 打印恢复的秘密
    println!("Reconstructed secret: {:?}", reconstructed_secret);

    // 判断原始秘密与恢复的秘密是否相等
    assert_eq!(secret, reconstructed_secret);
}

#[test]
fn test_feldman_vss() {
    let mut rng = OsRng;
    let g = ProjectivePoint::GENERATOR;
    let secret = Scalar::random(&mut rng);
    let n = 5;
    let t = 3;

    // 生成带有 Feldman 承诺的份额
    let (shares, commitments) = generate_shares_with_feldman_vss(secret, n, t, g, &mut rng);

    // 验证每个份额的有效性
    for share in &shares {
        assert!(verify_share_with_feldman_vss(*share, &commitments, g));
    }

    // 使用 t 个份额恢复秘密
    let reconstructed_secret = reconstruct_secret(&shares[0..t]);
    assert_eq!(secret, reconstructed_secret);

    // 篡改一个份额
    let mut tampered_shares = shares.clone();
    tampered_shares[0].1 += Scalar::ONE;
    assert!(!verify_share_with_feldman_vss(
        tampered_shares[0],
        &commitments,
        g
    ));

    // 使用篡改后的份额恢复秘密
    let tampered_reconstructed_secret = reconstruct_secret(&tampered_shares[0..t]);
    assert_ne!(secret, tampered_reconstructed_secret);
}

#[test]
fn test_pedersen_vss() {
    let mut rng = OsRng;
    let g = ProjectivePoint::GENERATOR;
    let num_tests = 100; // 增加测试次数

    for _ in 0..num_tests {
        // 随机生成 h，secret, n, t
        // 生成一个随机的标量（私钥）
        let random_scalar = Scalar::random(&mut rng);
        // 计算随机标量与基点的乘积，得到椭圆曲线上的一个点
        let h = g * random_scalar;
        let secret = Scalar::random(&mut rng);
        let n = rng.gen_range(3..=10); // 随机生成份额数量，至少为 3
        let t = rng.gen_range(2..=n); // 随机生成门限值，至少为 2 且不超过 n

        // 生成带有 Pedersen 承诺的份额
        let (shares, commitments, blinding_poly) =
            generate_shares_with_pedersen_vss(secret, n, t, g, h, &mut rng);

        // 验证每个份额的有效性
        for share in &shares {
            assert!(verify_share_with_pedersen_vss(
                *share,
                &commitments,
                &blinding_poly,
                g,
                h
            ));
        }

        // 随机选择 t 个份额进行恢复
        let mut selected_shares = shares.clone();
        selected_shares.shuffle(&mut rng);
        let reconstructed_secret = reconstruct_secret(&selected_shares[0..t]);
        assert_eq!(secret, reconstructed_secret);

        // 篡改一个份额
        let mut tampered_shares = shares.clone();
        let tamper_index = rng.gen_range(0..n); // 随机选择要篡改的份额
        tampered_shares[tamper_index].1 += Scalar::ONE;
        assert!(!verify_share_with_pedersen_vss(
            tampered_shares[tamper_index],
            &commitments,
            &blinding_poly,
            g,
            h
        ));

        // 使用篡改后的份额恢复秘密 (如果篡改的份额被选中)
        if tamper_index < t {
            let tampered_reconstructed_secret =
                reconstruct_secret(&tampered_shares[0..t]);
            assert_ne!(secret, tampered_reconstructed_secret);
        }
    }
    println!("All random tests passed for Pedersen VSS!");
}