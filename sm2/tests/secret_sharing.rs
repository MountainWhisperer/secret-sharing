use rand::rngs::OsRng;
use shamir_secret_sharing::share::{generate_shares, reconstruct_secret};
use sm2::Scalar;

#[test]
fn test_secret_sharing() {
    // 创建一个随机数生成器
    let mut rng = OsRng;
    // 设置要分享的秘密，这里是一个标量
    let secret = Scalar::from(123456789u64);
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