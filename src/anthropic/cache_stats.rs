//! 缓存统计伪造模块
//!
//! 为 new-api 计费端生成伪造的 cache_read_input_tokens 和 cache_creation_input_tokens，
//! 以减少计费成本。
//!
//! 注意：这只是伪造数据，Kiro 上游并不支持真正的 Claude Prompt Caching。

/// 缓存统计
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    /// 缓存读取 token 数（约 10% 价格）
    pub cache_read_input_tokens: i32,
    /// 缓存创建 token 数（约 125% 价格）
    pub cache_creation_input_tokens: i32,
}

/// 根据 input_tokens 生成伪造的缓存统计
///
/// 策略参考 Go 版本实现：
/// - cache_read_input_tokens: 占 input_tokens 的大部分（模拟高缓存命中率）
/// - cache_creation_input_tokens: 较小的值（模拟少量新缓存创建）
pub fn generate_fake_cache_stats(input_tokens: i32) -> CacheStats {
    if input_tokens <= 0 {
        return CacheStats {
            cache_read_input_tokens: 0,
            cache_creation_input_tokens: 0,
        };
    }

    // cache_read_input_tokens: 模拟高缓存命中
    // 基础值为 input_tokens 的 60-85%，加上随机波动
    let base_read_ratio = fastrand::u32(60..=85) as f64 / 100.0;
    let cache_read = (input_tokens as f64 * base_read_ratio) as i32;
    // 添加随机波动 ±5%
    let read_variance = fastrand::i32(-5..=5) as f64 / 100.0;
    let cache_read_input_tokens = ((cache_read as f64) * (1.0 + read_variance)) as i32;
    // 上限：不超过 input_tokens 的 90%，下限：至少 1000（如果 input_tokens 足够大）
    let cache_read_input_tokens = cache_read_input_tokens
        .min((input_tokens as f64 * 0.9) as i32)
        .max(input_tokens.min(1000));

    // cache_creation_input_tokens: 模拟少量新缓存
    // 基础值为 input_tokens 的 5-15%
    let base_creation_ratio = fastrand::u32(5..=15) as f64 / 100.0;
    let cache_creation = (input_tokens as f64 * base_creation_ratio) as i32;
    // 添加随机波动
    let creation_variance = fastrand::i32(0..=1000);
    let cache_creation_input_tokens = (cache_creation / 6 + creation_variance).min(25000);

    CacheStats {
        cache_read_input_tokens,
        cache_creation_input_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_fake_cache_stats_zero() {
        let stats = generate_fake_cache_stats(0);
        assert_eq!(stats.cache_read_input_tokens, 0);
        assert_eq!(stats.cache_creation_input_tokens, 0);
    }

    #[test]
    fn test_generate_fake_cache_stats_small() {
        let stats = generate_fake_cache_stats(100);
        assert!(stats.cache_read_input_tokens >= 0);
        assert!(stats.cache_read_input_tokens <= 100);
    }

    #[test]
    fn test_generate_fake_cache_stats_large() {
        let stats = generate_fake_cache_stats(100000);
        // cache_read 应该占大部分
        assert!(stats.cache_read_input_tokens >= 50000);
        assert!(stats.cache_read_input_tokens <= 90000);
        // cache_creation 应该较小
        assert!(stats.cache_creation_input_tokens <= 25000);
    }
}
