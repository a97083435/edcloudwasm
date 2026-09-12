/**
 * ============================================================================
 * TLS 1.2 & TLS 1.3 现代纯轻量级客户端实现
 * ============================================================================
 *
 * 本模块基于现代 Web 标准构建，不依赖 Node.js 内置的 `tls` 或 `crypto` 模块，
 * 主要面向 Cloudflare Workers；其他运行时也需要提供兼容的 Web Crypto、WHATWG Streams、
 * BYOB readable stream 以及本实现所用的椭圆曲线算法。
 *
 * 核心技术规范与协议依据:
 * - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3
 * - RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2
 * - RFC 5289: TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
 * - RFC 7748: Elliptic Curves for Security (X25519)
 * - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 * - RFC 6066: Transport Layer Security (TLS) Extensions: Extension Definitions (SNI 等)
 * - RFC 7627: Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension
 *
 * 支持的密码套件 (Cipher Suites):
 * 1. TLS 1.3:
 *    - 0x1301: TLS_AES_128_GCM_SHA256 (AEAD: AES-128-GCM, Hash: SHA-256)
 *    - 0x1302: TLS_AES_256_GCM_SHA384 (AEAD: AES-256-GCM, Hash: SHA-384)
 * 2. TLS 1.2:
 *    - 0xC02F: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 *    - 0xC030: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
 *    - 0xC02B: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
 *    - 0xC02C: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
 *
 * 支持的密钥交换曲线 (Supported Groups / Key Exchange Curves):
 * - X25519 (Group 29 / 0x001d) - 现代高性能 Montgomery 椭圆曲线
 * - Secp256r1 / P-256 (Group 23 / 0x0017) - NIST 标准 256 位 Weierstrass 椭圆曲线
 *
 * 架构设计与性能优化要点:
 * 1. 【W3C Web Cryptography API】: 密钥生成、ECDH 协商、HKDF/PRF 派生与 AES-GCM 加解密均委托
 *    给底层的 `crypto.subtle`；具体实现是否使用硬件加速及其侧信道属性由运行时决定。
 * 2. 【WHATWG Streams & BYOB I/O】: 底层网络传输抽象为 ReadableStream 与 WritableStream，
 *    在底层 readable stream 支持 BYOB 时使用预分配读取缓冲区；数据仍会复制到解析器缓冲区。
 * 3. 【双指针滑动窗口内存复用】: 自研 `BaseStreamBuffer`，通过指针平移与就地紧凑复制，
 *    减少 TCP 粘包/拆包处理过程中的重复分配；扩容时仍会分配并复制新的缓冲区。
 * 4. 【高吞吐流水线加解密】:
 *    - 写路径：大数据自动按 RFC 标准的 16KB 分片，8 块一组并发加密流水线发射。
 *    - 读路径：单批次多包并发批量解密，出错立即断开快速失败。
 * 5. 【防御性处理】:
 *    - 对 Uint8Array 输入创建副本，避免调用方在异步写入期间修改该输入；ArrayBuffer 输入仍由调用方负责其生命周期。
 *    - TLS 1.2 尾包合并为一次 WritableStream 写入，以减少写调用次数；这不保证 TCP 层的报文原子性。
 *    - 握手完成后清除部分握手状态的 JavaScript 引用，以便后续垃圾回收；这不等同于内存零化或密钥销毁。
 */
/** 全局单例 UTF-8 文本编码器，避免在热路径上频繁实例化带来不必要的内存与性能开销 */
const textEncoder = new TextEncoder();
/** 全局 0 长度 TypedArray，作为常量用于空 Salt、空 Context 等密码学派生入参 */
const EMPTY_BUFFER = new Uint8Array(0);
/**
 * 【性能优化】: 缓存当前运行时 Web Crypto 的 SubtleCrypto 接口实例，
 * 减少高频路径上的全局属性查找。
 */
const cryptoSubtle = crypto.subtle;
// ============================================================================
// 1. 基础工具函数：字节序列化与辅助操作
// ============================================================================
/**
 * 递归展平嵌套的数值、普通数组或 Uint8Array，生成一个单一连续的 Uint8Array
 *
 * 主要用于构造具有变长字段、多层扩展嵌套的 TLS 握手报文（如 ClientHello 及其扩展）。
 *
 * @param {...(number | number[] | Uint8Array | any[])} items - 待拼接的嵌套数据项；TypedArray 需为 Uint8Array
 * @returns {Uint8Array} 展平并拼接后的连续字节数组
 *
 * @example
 * concatBytes(0x16, [0x03, 0x01], new Uint8Array([0x00, 0x10]));
 * // => Uint8Array [ 0x16, 0x03, 0x01, 0x00, 0x10 ]
 */
function concatBytes(...items) {
    const bytes = [];
    const flatten = (list) => {
        for (const item of list) {
            if (item instanceof Uint8Array) {
                bytes.push(...item);
            } else if (Array.isArray(item)) {
                flatten(item);
            } else {
                bytes.push(item);
            }
        }
    };
    flatten(items);
    return new Uint8Array(bytes);
}
/**
 * 将 16 位无符号整数 (uint16) 转换为 2 字节的大端序 (Big-Endian / 网络字节序) 数组
 *
 * TLS 规范 (RFC 8446 / RFC 5246) 规定网络报文中所有多字节整数均采用大端序编码。
 *
 * @param {number} value - 待编码的 16 位无符号整数 (0 ~ 65535)
 * @returns {number[]} 包含 2 个字节的数组: [高8位, 低8位]
 */
const u16ToBytes = (value) => [value >> 8, value & 0xff];
/**
 * 从字节数组的指定偏移处读取一个 16 位大端序无符号整数 (uint16)
 *
 * 广泛用于解析 TLS 记录层长度、扩展类型、扩展长度及密码套件编号。
 *
 * @param {Uint8Array} buffer - 源字节数组
 * @param {number} offset - 读取的起始字节偏移量
 * @returns {number} 解析出的 16 位整数数值 (0 ~ 65535)
 */
const readU16BE = (buffer, offset) => (buffer[offset] << 8) | buffer[offset + 1];
/**
 * 将 64 位无符号大整数 (bigint / uint64) 编码为 8 字节大端序 TypedArray
 *
 * 【性能优化】:
 * 专用于 TLS 1.2 显式 Nonce (Explicit Nonce) 以及 AAD 序列号字段构造。
 * 通过 DataView 单次写入 64 位整型，消除小数组拼接分配与移位开销。
 *
 * @param {bigint} value - 待编码的 64 位无符号整数
 * @returns {Uint8Array} 8 字节的大端序字节数组
 */
function u64ToBytesBE(value) {
    const buffer = new Uint8Array(8);
    new DataView(buffer.buffer).setBigUint64(0, value);
    return buffer;
}
/**
 * 高性能合并多个 Uint8Array 块（单次内存分配并连续填充）
 *
 * 合并策略：
 * 1. 预先遍历所有传入分片，精确累加总字节长度；
 * 2. 一次性分配最终大小的连续 TypedArray 内存空间；
 * 3. 使用 TypedArray.prototype.set() 批量底层内存拷贝，避免逐字节 push 和多次数组扩容。
 *
 * @param {...(Uint8Array | undefined | null)} arrays - 待合并的 Uint8Array 数组列表
 * @returns {Uint8Array} 合并后的单一 Uint8Array 实例
 */
function concatUint8Arrays(...arrays) {
    const totalLength = arrays.reduce((sum, arr) => sum + (arr?.length || 0), 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        if (arr?.length) {
            result.set(arr, offset);
            offset += arr.length;
        }
    }
    return result;
}
/**
 * 根据密码学哈希算法名称获取对应的输出摘要字节长度 (HashLen)
 *
 * - SHA-384: 48 字节 (384 位)
 * - SHA-256: 32 字节 (256 位)
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 标准哈希算法名称
 * @returns {number} 哈希摘要字节长度（32 或 48）
 */
const getHashLength = (hashName) => (hashName === "SHA-384" ? 48 : 32);
/**
 * 检查接收到的 Alert 报文是否为非致命的 SNI 不匹配告警
 *
 * 根据 RFC 6066 Section 3 (Server Name Indication):
 * 某些服务端可能在 SNI 不匹配时返回 AlertLevel=1 (Warning), AlertDescription=112
 * (unrecognized_name)。RFC 并不保证服务端随后一定继续握手或使用默认证书；调用方应根据
 * 自身的 SNI 和证书校验策略决定是否继续。
 *
 * @param {Uint8Array} alertBytes - 2 字节的 Alert 负载: [Level(1B), Description(1B)]
 * @returns {boolean} 若为 Warning (1) 且 unrecognized_name (112) 则返回 true
 */
const isUnrecognizedNameAlert = (alertBytes) => alertBytes?.[0] === 1 && alertBytes[1] === 112;
// ============================================================================
// 2. Web Crypto API 封装：加解密与摘要计算
// ============================================================================
/**
 * 基于 Web Crypto API 计算 HMAC 消息认证码
 *
 * 兼容处理两种密钥形式：原始密钥字节数组 (`Uint8Array`) 或已导入的 Web Crypto `CryptoKey` 对象。
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 底层哈希算法名称
 * @param {Uint8Array | CryptoKey} key - HMAC 密钥材料（Uint8Array 格式将自动临时导入为 CryptoKey）
 * @param {Uint8Array} data - 参与 HMAC 签名的输入数据
 * @returns {Promise<Uint8Array>} 计算生成的 HMAC 签名结果字节数组
 */
async function hmacSign(hashName, key, data) {
    const cryptoKey = key.type
        ? key
        : await cryptoSubtle.importKey("raw", key, {name: "HMAC", hash: hashName}, false, ["sign"]);
    return new Uint8Array(await cryptoSubtle.sign("HMAC", cryptoKey, data));
}
/**
 * 基于 Web Crypto API 计算数据的密码学单向哈希散列值 (SHA-256 / SHA-384)
 *
 * 用于握手转录哈希 (Transcript Hash) 计算以及 HKDF 派生流程。
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 哈希算法名称
 * @param {Uint8Array} data - 待计算摘要的原始数据
 * @returns {Promise<Uint8Array>} 摘要计算结果 (SHA-256: 32B, SHA-384: 48B)
 */
async function hashDigest(hashName, data) {
    return new Uint8Array(await cryptoSubtle.digest(hashName, data));
}
/**
 * 将原始对称密钥字节数组导入为 Web Crypto 的 AES-GCM CryptoKey 句柄
 *
 * `extractable = false` 会阻止通过 Web Crypto API 导出该 CryptoKey；它不保证底层内存零化，
 * 也不能替代应用层的密钥生命周期管理。
 *
 * @param {Uint8Array} rawKey - 16 字节 (AES-128) 或 32 字节 (AES-256) 原始对称密钥
 * @param {("encrypt"|"decrypt")} usage - 密钥用途 ("encrypt" 用于发送通道, "decrypt" 用于接收通道)
 * @returns {Promise<CryptoKey>} 导入生成的不可导出 CryptoKey 实例
 */
function importAesGcmKey(rawKey, usage) {
    return cryptoSubtle.importKey("raw", rawKey, {name: "AES-GCM"}, false, [usage]);
}
/**
 * 执行 AES-GCM 认证加密 (Authenticated Encryption)
 *
 * Web Crypto 的 AES-GCM 加密输出包含：密文 (Ciphertext) + 16 字节的 GCM 认证标签 (Auth Tag)。
 *
 * @param {CryptoKey} key - AES-GCM 加密密钥
 * @param {Uint8Array} iv - 12 字节初始化向量 (Initialization Vector / Nonce)
 * @param {Uint8Array} plaintext - 待加密明文数据
 * @param {Uint8Array} additionalData - 关联认证数据 (AAD - Additional Authenticated Data)，只认证不加密
 * @returns {Promise<Uint8Array>} 密文与认证标签的拼接结果 (长度 = 明文长度 + 16 字节 Tag)
 */
async function aesGcmEncrypt(key, iv, plaintext, additionalData) {
    return new Uint8Array(
        await cryptoSubtle.encrypt({name: "AES-GCM", iv, additionalData}, key, plaintext)
    );
}
/**
 * 执行 AES-GCM 认证解密 (Authenticated Decryption)
 *
 * 同时验证密文数据和 AAD 的完整性。若密文被篡改或 Tag 校验失败，
 * 底层 Web Crypto 将直接抛出 OperationError 异常，杜绝伪造报文被解密执行。
 *
 * @param {CryptoKey} key - AES-GCM 解密密钥
 * @param {Uint8Array} iv - 12 字节初始化向量 (Nonce)
 * @param {Uint8Array} ciphertext - 包含末尾 16 字节认证标签的完整密文负载
 * @param {Uint8Array} additionalData - 关联认证数据 (AAD)
 * @returns {Promise<Uint8Array>} 解密恢复的原始明文数据
 * @throws {Error} 认证标签校验失败或密文损坏时抛出异常
 */
async function aesGcmDecrypt(key, iv, ciphertext, additionalData) {
    return new Uint8Array(
        await cryptoSubtle.decrypt({name: "AES-GCM", iv, additionalData}, key, ciphertext)
    );
}
/**
 * 打包 TLS 记录层 (Record Layer) 报文
 *
 * TLS 记录层格式规范 (RFC 5246 / RFC 8446 Section 5.1):
 * ```
 * +------------------+------------------+------------------+
 * | ContentType (1B) |   Version (2B)   |   Length (2B)    |
 * +------------------+------------------+------------------+
 * |                 Fragment (Length 字节)                 |
 * +--------------------------------------------------------+
 * ```
 * 常见 ContentType 魔数:
 * - 20 (0x14): ChangeCipherSpec
 * - 21 (0x15): Alert
 * - 22 (0x16): Handshake
 * - 23 (0x17): Application Data
 *
 * 版本号说明:
 * - 0x0303 (TLS 1.2): 广泛兼容默认值。在 TLS 1.3 中，为穿透历史网络中间盒 (Middlebox)，
 *   所有加密记录层的外层伪装版本号强制固定为 0x0303 (RFC 8446 Appendix D.4)。
 * - 0x0301 (TLS 1.0): 初始发送未加密 ClientHello 时使用的版本号。
 *
 * @param {number} contentType - 记录层协议类型 (20: CCS, 21: Alert, 22: Handshake, 23: Application Data)
 * @param {Uint8Array} fragment - 记录层承载的有效负载片段
 * @param {number} [version=0x0303] - 记录层 2 字节版本号 (默认 0x0303 即 TLS 1.2)
 * @param {number} [length=fragment.length] - 负载字节长度 (大端序写入)
 * @returns {Uint8Array} 包含 5 字节头部与负载的完整 TLS 记录帧
 */
function wrapTlsRecord(contentType, fragment, version = 0x0303, length = fragment.length) {
    const record = new Uint8Array(5 + length);
    // 直接索引写入 5 字节记录层头部，避免显式创建临时小数组
    record[0] = contentType;
    record[1] = version >> 8;
    record[2] = version & 0xff;
    record[3] = length >> 8;
    record[4] = length & 0xff;
    record.set(fragment, 5);
    return record;
}
/**
 * 打包 TLS 握手层 (Handshake Layer) 消息报文
 *
 * TLS 握手消息格式规范:
 * ```
 * +--------------------+-----------------------------------+
 * | HandshakeType (1B) |       Length (3B, 24 位无符号大端)  |
 * +--------------------+-----------------------------------+
 * |                     Body (Length 字节)                  |
 * +--------------------------------------------------------+
 * ```
 * 常见 HandshakeType 魔数:
 * - 1  (0x01): ClientHello
 * - 2  (0x02): ServerHello
 * - 11 (0x0b): Certificate
 * - 12 (0x0c): ServerKeyExchange (TLS 1.2)
 * - 13 (0x0d): CertificateRequest
 * - 14 (0x0e): ServerHelloDone (TLS 1.2)
 * - 16 (0x10): ClientKeyExchange (TLS 1.2)
 * - 20 (0x14): Finished
 *
 * @param {number} handshakeType - 握手消息类型编号 (1B)
 * @param {Uint8Array | number[]} body - 握手消息体数据
 * @param {number} [length=body.length] - 消息体字节长度 (写入 3 字节 uint24 大端序)
 * @returns {Uint8Array} 包含 4 字节头部与消息体的完整握手消息
 */
function wrapHandshakeMessage(handshakeType, body, length = body.length) {
    const message = new Uint8Array(4 + length);
    // 直接按字节索引写入 4 字节握手头部，避免显式创建临时 JS Array
    message[0] = handshakeType;
    message[1] = (length >> 16) & 0xff;
    message[2] = (length >> 8) & 0xff;
    message[3] = length & 0xff;
    message.set(body, 4);
    return message;
}
/**
 * 构造 TLS 1.3 记录层关联认证数据 (AAD - Additional Authenticated Data)
 *
 * 根据 RFC 8446 Section 5.2 规范:
 * TLS 1.3 AEAD 的 AAD 严格固定为 5 字节记录层伪首部:
 * - opaque_type (1B): 固定为 0x17 (23，即 Application Data)
 * - legacy_record_version (2B): 固定为 0x0303 (TLS 1.2)
 * - length (2B): 密文的实际字节长度 (包含明文长度 + 隐藏的真实类型 1B + Padding + 16B 认证标签)
 *
 * @param {number} length - 加密后的记录层负载总长度 (Ciphertext + 16B Tag)
 * @returns {Uint8Array} 5 字节的标准 TLS 1.3 AAD: `[23, 3, 3, len_high, len_low]`
 */
function createTls13Aad(length) {
    const aad = new Uint8Array(5);
    aad[0] = 23;
    aad[1] = 3;
    aad[2] = 3;
    aad[3] = length >> 8;
    aad[4] = length & 0xff;
    return aad;
}
// ============================================================================
// 3. TLS 密码学算法：密钥交换、PRF 与 HKDF 派生
// ============================================================================
/**
 * TLS 1.2 伪随机数函数 (PRF - Pseudo-Random Function, 基于 P_hash 数据扩展)
 *
 * 依据 RFC 5246 Section 5 规范:
 * TLS 1.2 使用单哈希 PRF (通常为 SHA-256 或 SHA-384):
 * ```
 * PRF(secret, label, seed) = P_<hash>(secret, label + seed)
 *
 * P_hash 展开算法:
 *   A(0) = seed (即 label + seed)
 *   A(1) = HMAC_hash(secret, A(0))
 *   A(2) = HMAC_hash(secret, A(1))
 *   ...
 *   P_hash = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
 * ```
 * 迭代执行直至生成的字节流满足所需的输出长度，最后进行截断。
 *
 * @param {Uint8Array | CryptoKey} secret - 预主密钥 (Pre-Master Secret) 或主密钥 (Master Secret)
 * @param {string} label - ASCII 标签字符串 (如 "master secret", "key expansion", "client finished")
 * @param {Uint8Array} seed - 种子材料 (如 ClientRandom 与 ServerRandom 的拼接)
 * @param {number} length - 需要派生的伪随机字节总长度
 * @param {("SHA-256"|"SHA-384")} [hashName="SHA-256"] - 协商套件指定的哈希算法
 * @returns {Promise<Uint8Array>} 派生生成的伪随机字节数组 (长度严格等于 length)
 */
async function prfTls12(secret, label, seed, length, hashName = "SHA-256") {
    // 按照规范拼接: label (ASCII 编码) || seed
    const labelAndSeed = concatUint8Arrays(textEncoder.encode(label), seed);
    const key = secret.type
        ? secret
        : await cryptoSubtle.importKey("raw", secret, {name: "HMAC", hash: hashName}, false, ["sign"]);
    let result = new Uint8Array(0);
    let a = labelAndSeed; // A(0) = seed
    // 迭代生成 HMAC 链并累加结果
    while (result.length < length) {
        a = await hmacSign(hashName, key, a); // A(i) = HMAC(secret, A(i-1))
        const step = await hmacSign(hashName, key, concatUint8Arrays(a, labelAndSeed));
        result = concatUint8Arrays(result, step);
    }
    return result.slice(0, length);
}
/**
 * HKDF-Extract: 提取伪随机密钥 (PRK - Pseudorandom Key)
 *
 * 依据 RFC 5869 / RFC 8446 Section 7.1:
 * ```
 * PRK = HMAC-Hash(salt, IKM)
 * ```
 * 若 salt 为 null 或空，则规范要求填充长度为 HashLen 的全零字节数组作为 salt。
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 底层哈希算法名称
 * @param {Uint8Array | null} salt - 盐值（可为空）
 * @param {Uint8Array} ikm - 输入密钥材料 (Input Keying Material, 如 ECDH 共享秘密)
 * @returns {Promise<Uint8Array>} 提取出的 PRK (长度为 HashLen)
 */
function hkdfExtract(hashName, salt, ikm) {
    const saltBuffer = salt?.length ? salt : new Uint8Array(getHashLength(hashName));
    return hmacSign(hashName, saltBuffer, ikm);
}
/**
 * TLS 1.3 HKDF-Expand-Label (RFC 8446 Section 7.1)
 *
 * TLS 1.3 核心密钥派生基础函数，用于从 PRK 扩展出各类会话秘钥及下一阶段的 Derived Secret。
 * 内部构造符合 RFC 规范的 HkdfLabel 结构:
 * ```
 * struct {
 *     uint16 length = length;
 *     opaque label<7..255> = "tls13 " + Label;
 *     opaque context<0..255> = Context;
 * } HkdfLabel;
 * ```
 * 然后计算: `HKDF-Expand(PRK, HkdfLabel, length)`
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 哈希算法名称
 * @param {Uint8Array | CryptoKey} prk - 伪随机密钥 PRK
 * @param {string | Uint8Array} label - 标签；字符串会自动添加 "tls13 " 前缀，字节数组需由调用方自行提供完整标签
 * @param {Uint8Array} context - 上下文信息（通常为握手消息转录摘要 Transcript Hash）
 * @param {number} length - 期望输出的密钥字节长度
 * @returns {Promise<Uint8Array>} 派生出的子密钥字节数组
 */
async function hkdfExpandLabel(hashName, prk, label, context, length) {
    const labelBytes = typeof label === "string" ? textEncoder.encode("tls13 " + label) : label;
    const hashLen = getHashLength(hashName);
    // 序列化 HkdfLabel 结构体
    const hkdfLabel = concatBytes(
        u16ToBytes(length),
        labelBytes.length,
        labelBytes,
        context.length,
        context
    );
    const key = prk.type
        ? prk
        : await cryptoSubtle.importKey("raw", prk, {name: "HMAC", hash: hashName}, false, ["sign"]);
    let result = new Uint8Array(0);
    let t = new Uint8Array(0);
    const iterations = Math.ceil(length / hashLen);
    // HKDF-Expand 迭代: T(i) = HMAC(PRK, T(i-1) || info || i)
    for (let i = 1; i <= iterations; i++) {
        t = await hmacSign(hashName, key, concatUint8Arrays(t, hkdfLabel, [i]));
        result = concatUint8Arrays(result, t);
    }
    return result.slice(0, length);
}
/**
 * 本地生成 ECDH (P-256) 或 X25519 临时密钥对
 *
 * @param {("P-256"|"X25519")} [namedCurve="P-256"] - 曲线类型名称
 * @returns {Promise<{kp: CryptoKeyPair, pk: Uint8Array}>} 包含 CryptoKeyPair 与原始公钥字节的封装对象
 * - P-256 公钥为 65 字节非压缩格式点: `0x04 || X (32B) || Y (32B)`
 * - X25519 公钥为 32 字节 u 坐标原始点
 */
async function generateEcdhKeyPair(namedCurve = "P-256") {
    const isX25519 = namedCurve === "X25519";
    const keyPair = await cryptoSubtle.generateKey(
        isX25519 ? {name: "X25519"} : {name: "ECDH", namedCurve},
        true,
        ["deriveBits"]
    );
    const rawPublicKey = new Uint8Array(await cryptoSubtle.exportKey("raw", keyPair.publicKey));
    return {kp: keyPair, pk: rawPublicKey};
}
/**
 * 基于本端私钥与对端公钥计算 Diffie-Hellman 共享秘密 (Shared Secret)
 *
 * @param {CryptoKey} privateKey - 本地生成的临时私钥
 * @param {Uint8Array} peerPublicKeyRaw - 服务端通过 ServerKeyExchange 或 key_share 扩展返回的原始公钥
 * @param {("P-256"|"X25519")} [namedCurve="P-256"] - 椭圆曲线名称
 * @returns {Promise<Uint8Array>} 256 位 (32 字节) 协商生成的原始共享秘密
 */
async function deriveSharedSecret(privateKey, peerPublicKeyRaw, namedCurve = "P-256") {
    const isX25519 = namedCurve === "X25519";
    const peerPublicKey = await cryptoSubtle.importKey(
        "raw",
        peerPublicKeyRaw,
        isX25519 ? {name: "X25519"} : {name: "ECDH", namedCurve},
        false,
        []
    );
    return new Uint8Array(
        await cryptoSubtle.deriveBits(
            {name: isX25519 ? "X25519" : "ECDH", public: peerPublicKey},
            privateKey,
            256
        )
    );
}
/**
 * TLS 1.3 派生具体传输方向的工作密钥 (Traffic Key) 与基础初始向量 (Base IV)
 *
 * 依据 RFC 8446 Section 7.3:
 * ```
 * [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
 * [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
 * ```
 *
 * @param {("SHA-256"|"SHA-384")} hashName - 哈希算法名称
 * @param {Uint8Array | CryptoKey} secret - 流量秘钥源 (如 client_handshake_traffic_secret 或 client_application_traffic_secret)
 * @param {number} keyLen - 对称密钥长度 (AES-128: 16, AES-256: 32)
 * @param {number} ivLen - 初始向量长度 (固定为 12 字节)
 * @param {("encrypt"|"decrypt")} usage - 密钥用途
 * @returns {Promise<[CryptoKey, Uint8Array]>} 二元组: [已导入的 AES-GCM CryptoKey 实例, 12 字节的基础 IV]
 */
async function deriveTrafficKeys(hashName, secret, keyLen, ivLen, usage) {
    const prk = secret.type
        ? secret
        : await cryptoSubtle.importKey("raw", secret, {name: "HMAC", hash: hashName}, false, ["sign"]);
    // 并行计算 key 与 iv 派生，提升握手效率
    const [keyBytes, ivBytes] = await Promise.all([
        hkdfExpandLabel(hashName, prk, "key", EMPTY_BUFFER, keyLen),
        hkdfExpandLabel(hashName, prk, "iv", EMPTY_BUFFER, ivLen)
    ]);
    return [await importAesGcmKey(keyBytes, usage), ivBytes];
}
/**
 * 解析 TLS 1.3 解密后的内层明文 (TLSInnerPlaintext)
 *
 * TLS 1.3 协议规范 (RFC 8446 Section 5.4):
 * 为混淆流量真实内容类型并隐藏报文长度（防御基于报文尺寸的流量侧信道分析），
 * 明文末尾依次存放真实的 ContentType 与任意长度的 0x00 填充字节:
 * ```
 * struct {
 *     opaque content[TLSPlaintext.length];
 *     ContentType type;
 *     uint8 zeros[length_of_padding];
 * } TLSInnerPlaintext;
 * ```
 * 本函数从尾部逆向扫描，剥离所有 0x00 填充，提取第一个非零字节作为真实协议类型，前面剩余字节为真实数据。
 *
 * @param {Uint8Array} buffer - AES-GCM 解密后的内层明文原始字节
 * @returns {{data: Uint8Array, type: number}} 解析出的真实数据载荷与其 ContentType
 * @throws {Error} 若整个明文全为 0 且无有效 ContentType，则抛出协议格式错误
 */
function unpadTls13Plaintext(buffer) {
    let index = buffer.length - 1;
    // 从末尾跳过所有零填充字节
    while (index >= 0 && !buffer[index]) {
        index--;
    }
    if (index < 0) {
        throw new Error("Invalid TLS 1.3 padding");
    }
    return {
        data: buffer.subarray(0, index),
        type: buffer[index]
    };
}
/**
 * TLS 1.3 Per-Record Nonce (IV) 掩码计算
 *
 * 依据 RFC 8446 Section 5.3 规范:
 * TLS 1.3 不再显式传输 Nonce，而是将 64 位记录序号 (sequence_number)
 * 转换为 8 字节大端序（左侧隐式高位补零至 12 字节），与 12 字节的基础 IV 进行异或运算:
 * ```
 * nonce = iv ^ padded_seq_num
 * ```
 * 该机制要求同一密钥下的记录序号不重复；序号管理本身仍需由连接状态保证。
 *
 * @param {Uint8Array} iv - 12 字节的基础 IV (Base IV)
 * @param {bigint} seqNum - 64 位无符号包序列号 (0n, 1n, 2n...)
 * @returns {Uint8Array} 按给定记录序号计算出的 12 字节 Nonce；是否唯一取决于序号管理
 */
function xorIv(iv, seqNum) {
    const result = iv.slice();
    // 将序号的大端表示与基础 IV 的末 8 字节进行 XOR；具体性能取决于运行时实现。
    const view = new DataView(result.buffer, result.byteOffset + result.length - 8, 8);
    view.setBigUint64(0, view.getBigUint64(0) ^ seqNum);
    return result;
}
// ============================================================================
// 4. 流式数据包解析器 (带内存紧凑复用)
// ============================================================================
/**
 * 基础双指针滑动窗口流缓冲区 (BaseStreamBuffer)
 *
 * 内存与性能设计哲学:
 * 1. 采用双指针模型: `head` 为当前读指针，`tail` 为当前写指针，有效数据范围为 `[head, tail)`；
 * 2. 内存紧凑就地平移: 当缓冲区右侧空间不足且左侧已消费空间较大时，使用 `copyWithin` 将未读数据平移回起始位置，
 *    避免频繁分配新 TypedArray 造成 V8 堆内存碎片和频繁 GC 回收；
 * 3. 动态几何扩容: 当未读数据与新增数据之和超出当前容量时，按 2 倍比例动态扩容。
 */
class BaseStreamBuffer {
    /**
     * @param {number} initialSize - 缓冲区初始分配的字节容量
     */
    constructor(initialSize) {
        this.buffer = new Uint8Array(initialSize);
        this.head = 0; // 数据读取游标 (Read Cursor)
        this.tail = 0; // 数据写入游标 (Write Cursor)
    }
    /**
     * 向缓冲区追加网络流入的原始数据块
     *
     * @param {Uint8Array} data - 新到达的字节数据
     */
    feed(data) {
        // 【性能优化】: 缓存 this 为局部变量，减少属性查找
        const self = this;
        if (self.tail + data.length > self.buffer.length) {
            const unreadLength = self.tail - self.head;
            const needsResize = unreadLength + data.length > self.buffer.length;
            const newBuf = needsResize
                ? new Uint8Array(Math.max(self.buffer.length * 2, unreadLength + data.length))
                : self.buffer;
            if (needsResize) {
                // 扩容路径: 将未读数据迁移到新申请的大内存中
                newBuf.set(self.buffer.subarray(self.head, self.tail));
            } else {
                // 紧凑路径: 原地平移未读数据至缓冲区头部 [0, unreadLength)
                newBuf.copyWithin(0, self.head, self.tail);
            }
            self.buffer = newBuf;
            self.tail = unreadLength;
            self.head = 0;
        }
        // 紧接着在 tail 处写入新数据
        self.buffer.set(data, self.tail);
        self.tail += data.length;
    }
}
/**
 * TLS 记录层 (Record Layer) 流解析器
 *
 * 职责:
 * 处理底层 TCP 流的粘包与半包分片，从连续流中按 TLS 记录层协议头切分出独立的 Record 帧。
 */
class RecordParser extends BaseStreamBuffer {
    constructor() {
        super(32768); // 初始分配 32KB 记录解析缓冲区
    }
    /**
     * 尝试从流中提取下一个完整的 TLS 记录帧
     *
     * @returns {{type: number, version: number, length: number, fragment: Uint8Array} | null}
     * - 若当前缓冲区数据足以构成一个完整的记录帧，则返回解析出的对象；
     * - 若数据不完整（半包）则返回 null，等待后续数据到达。
     * @throws {Error} 若记录长度超过本解析器采用的 18432 字节上限。
     * TLS 1.2 的 TLSCiphertext 上限为 2^14 + 2048，TLS 1.3 的上限为 2^14 + 256；
     * 本解析器在解析阶段尚未区分协商版本，因此调用方仍需执行版本相关校验。
     */
    next() {
        // 【性能优化】: 缓存 this 引用至 self
        const self = this;
        if (self.tail - self.head < 5) return null; // 头部不足 5 字节，继续等待
        const type = self.buffer[self.head];
        const version = readU16BE(self.buffer, self.head + 1);
        const length = readU16BE(self.buffer, self.head + 3);
        // 这里使用 TLS 1.2 的 2^14 + 2048 作为通用解析上限；TLS 1.3 的协议上限更小。
        if (length > 18432) {
            throw new Error("TLS record length exceeds maximum allowed limit");
        }
        if (self.tail - self.head < 5 + length) return null; // 负载数据尚未完整到达
        // 零拷贝提取当前记录的负载切片，并推进读指针
        const fragment = self.buffer.subarray(self.head + 5, (self.head += 5 + length));
        // 若当前未读数据已被全部消费完，直接归零游标，实现最高效的原地复用
        if (self.head === self.tail) {
            self.head = self.tail = 0;
        }
        return {type, version, length, fragment};
    }
}
/**
 * TLS 握手层 (Handshake Layer) 消息流解析器
 *
 * 职责:
 * 处理握手消息跨 Record 记录分片或单个 Record 包含多条握手消息的情况，按 4 字节握手头切分出完整的握手消息。
 */
class HandshakeParser extends BaseStreamBuffer {
    constructor() {
        super(4096); // 初始分配 4KB 握手消息解析缓冲区
    }
    /**
     * 尝试提取下一条完整的 TLS 握手消息
     *
     * @returns {{type: number, length: number, body: Uint8Array, raw: Uint8Array} | null}
     * - type: 握手消息类型 (如 1: ClientHello, 2: ServerHello, 11: Certificate 等)
     * - length: 握手消息体长度 (uint24)
     * - body: 握手消息体数据载荷
     * - raw: 包含 4 字节头部的完整原始握手消息（必须用于转录哈希 transcript 计算）
     */
    next() {
        // 【性能优化】: 缓存 this 引用至 self
        const self = this;
        if (self.tail - self.head < 4) return null; // 头部不足 4 字节
        const type = self.buffer[self.head];
        const length = (self.buffer[self.head + 1] << 16) | readU16BE(self.buffer, self.head + 2);
        if (self.tail - self.head < 4 + length) return null; // 消息体未接收完整
        const body = self.buffer.subarray(self.head + 4, self.head + 4 + length);
        const raw = self.buffer.subarray(self.head, (self.head += 4 + length));
        if (self.head === self.tail) {
            self.head = self.tail = 0;
        }
        return {type, length, body, raw};
    }
}
// ============================================================================
// 5. 报文构造：ClientHello
// ============================================================================
/**
 * 构造符合 TLS 1.2 与 TLS 1.3 双协议向前兼容的 ClientHello 握手报文
 *
 * 协议结构规范 (RFC 8446 Section 4.1.2 & RFC 5246 Section 7.4.1.2):
 * ```
 * uint16 client_version = 0x0303; // TLS 1.2 (兼容中间盒)
 * opaque random[32];              // ClientRandom
 * uint8 legacy_session_id<0..32>; // TLS 1.3 中间盒兼容模式伪装 SessionID
 * uint16 cipher_suites<2..2^16-2>;// 客户端支持的密码套件列表
 * uint8 legacy_compression_methods<1..2^8-1> = [0]; // null 压缩
 * Extension extensions<8..2^16-1>;// 客户端扩展列表
 * ```
 *
 * 扩展列表配置:
 * 1. renegotiation_info (0xff01): 声明安全重协商支持 (RFC 5746)；该扩展本身不替代完整的重协商状态校验
 * 2. server_name (0x0000): SNI 扩展，传递目标虚拟主机名 (RFC 6066)
 * 3. ec_point_formats (0x000b): 表明支持未压缩椭圆曲线点 (uncompressed: 0)
 * 4. supported_groups (0x000a): 声明支持的椭圆曲线 (29: X25519, 23: secp256r1)
 * 5. signature_algorithms (0x000d): 声明支持的数字签名算法组合
 * 6. supported_versions (0x002b): TLS 1.3 核心版本协商扩展 (0x0304 TLS 1.3, 0x0303 TLS 1.2)
 * 7. psk_key_exchange_modes (0x002d): 声明 PSK 密钥交换模式 (psk_dhe_ke: 1)
 * 8. key_share (0x0033): 预先发送 X25519 与 P-256 两条曲线的公钥，减少 HelloRetryRequest 的概率
 *
 * @param {Uint8Array} clientRandom - 客户端生成的 32 字节密码学强随机数
 * @param {string} serverName - 目标 SNI 服务器域名
 * @param {{x25519: Uint8Array, p256: Uint8Array}} keyShares - 预先生成的两条曲线的公钥材料
 * @param {Object} [options={}] - 可选配置项
 * @param {Uint8Array} [options.sessionId=EMPTY_BUFFER] - 要发送的会话 ID；默认为空。长度应符合 TLS 的 0..32 字节限制
 * @returns {Uint8Array} 包装好的完整 ClientHello 握手报文（含 4 字节握手头）
 */
function buildClientHello(clientRandom, serverName, keyShares, {sessionId = EMPTY_BUFFER} = {}) {
    // 支持的密码套件列表 (按协商优先级排列):
    // 0x1301 (4865): TLS_AES_128_GCM_SHA256 (TLS 1.3)
    // 0x1302 (4866): TLS_AES_256_GCM_SHA384 (TLS 1.3)
    // 0xC02F (49199): TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    // 0xC030 (49200): TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
    // 0xC02B (49195): TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)
    // 0xC02C (49196): TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2)
    const cipherSuites = concatBytes(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(u16ToBytes));
    const extensions = [
        // 扩展: renegotiation_info (RFC 5746, 扩展码: 0xff01, 长度: 1, 载荷: 0x00)
        concatBytes(0xff, 1, 0, 1, 0)
    ];
    // 扩展: server_name (SNI - RFC 6066, 扩展码: 0x0000)
    if (serverName) {
        const hostBytes = textEncoder.encode(serverName);
        extensions.push(
            concatBytes(
                0, 0, // extension_type: 0 (server_name)
                u16ToBytes(hostBytes.length + 5), // extension_data 长度
                u16ToBytes(hostBytes.length + 3), // server_name_list 长度
                0,                                // name_type: 0 (host_name)
                u16ToBytes(hostBytes.length),     // host_name 长度
                hostBytes                         // host_name 字节序列
            )
        );
    }
    // 预组装 key_share (RFC 8446): 同时携带 X25519 (29) 与 P-256 (23) 两个 Group 的公钥材料。
    // 当服务端选择其中一条曲线时通常可避免 HelloRetryRequest；其他服务端策略仍可能触发 HRR。
    const keyShareEntries = concatUint8Arrays(
        concatBytes(0, 29, u16ToBytes(keyShares.x25519.length), keyShares.x25519),
        concatBytes(0, 23, u16ToBytes(keyShares.p256.length), keyShares.p256)
    );
    extensions.push(
        // 扩展: ec_point_formats (RFC 4492/8422, 扩展码: 11, 支持 uncompressed: 0)
        concatBytes(u16ToBytes(11), 0, 2, 1, 0),
        // 扩展: supported_groups (RFC 8422/8446, 扩展码: 10, 支持 29: X25519, 23: secp256r1)
        concatBytes(u16ToBytes(10), 0, 6, 0, 4, 0, 29, 0, 23),
        // 扩展: signature_algorithms (RFC 8446, 扩展码: 13, 支持的数字签名组合列表)
        // 包含 RSA-PSS, ECDSA-SECP256R1-SHA256, RSA-PKCS1 等常见组合
        concatBytes(
            u16ToBytes(13),
            0, 34, // 扩展载荷总长度 (34 字节)
            0, 32, // 签名算法列表总长度 (16 个算法 * 2 字节 = 32 字节)
            ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(u16ToBytes)
        ),
        // 扩展: supported_versions (RFC 8446, 扩展码: 43) -> 优先协商 TLS 1.3 (0x0304)，允许降级 TLS 1.2 (0x0303)
        concatBytes(u16ToBytes(43), 0, 5, 4, 3, 4, 3, 3),
        // 扩展: key_share (RFC 8446, 扩展码: 51) -> 发送上述准备好的双曲线 ClientShares
        concatBytes(u16ToBytes(51), u16ToBytes(keyShareEntries.length + 2), u16ToBytes(keyShareEntries.length), keyShareEntries)
    );
    const serializedExtensions = concatUint8Arrays(...extensions);
    return wrapHandshakeMessage(
        1, // HandshakeType: 1 (ClientHello)
        concatBytes(
            u16ToBytes(0x0303), // legacy_version: 固定 0x0303 (TLS 1.2 兼容伪装)
            clientRandom,       // 32 字节客户端随机数
            sessionId.length,   // 会话 ID 长度 (Middlebox 模式下为 32)
            sessionId,          // 会话 ID 载荷
            u16ToBytes(cipherSuites.length), // 密码套件列表长度
            cipherSuites,       // 密码套件列表
            1, 0,               // legacy_compression_methods (长度 1, 0x00 表示 null 不压缩)
            u16ToBytes(serializedExtensions.length), // 扩展总长度
            serializedExtensions // 所有扩展的序列化字节
        )
    );
}
// ============================================================================
// 6. TLS 客户端实现主体 (TlsClient)
// ============================================================================
/**
 * TLS 1.2 / TLS 1.3 双协议自适应轻量级客户端
 *
 * 核心功能与职责:
 * 1. 负责执行握手报文收发、ServerHello 匹配、ECDH 密钥协商和 TLS 密钥派生；当前实现不校验服务端证书链、CertificateVerify 或 Finished verify_data；
 * 2. 状态机管理与流量秘钥生命周期维护；
 * 3. 驱动底层的 WHATWG Streams 进行应用层数据加解密传输 (`write` / `read`)；
 * 4. 异常处理、Alert 告警响应与优雅挥手关闭 (`close`)。
 */
class TlsClient {
    /**
     * 创建一个新的 TLS 客户端实例
     *
     * @param {Object} socket - 底层双向流套接字对象，必须遵循 WHATWG Streams 规范
     * @param {ReadableStream<Uint8Array>} socket.readable - 底层网络输入字节流，需支持 BYOB reader
     * @param {WritableStream<Uint8Array>} socket.writable - 底层网络输出流
     * @param {() => void} [socket.close] - 底层网络关闭方法
     * @param {Object} [options={}] - 可选配置对象
     * @param {string} [options.serverName=""] - 目标 SNI 主机名（若为空则不发送 SNI 扩展）
     */
    constructor(socket, options = {}) {
        /** @type {Object} 底层物理传输套接字 */
        this.socket = socket;
        /** @type {string} SNI 服务器主机名 */
        this.serverName = options.serverName || "";
        /** @type {Uint8Array} 客户端生成的 32 字节密码学安全随机数 (ClientRandom) */
        this.clientRandom = crypto.getRandomValues(new Uint8Array(32));
        /** 明确不支持会话恢复，Session ID 长度固定为 0 */
        this.sessionId = EMPTY_BUFFER;
        /** @type {Uint8Array} 握手转录报文缓冲区 (Transcript Buffer)，用于计算握手相关派生值 */
        this.transcriptBuffer = new Uint8Array(8192);
        /** @type {number} 当前已记录的握手转录报文字节长度 */
        this.transcriptLen = 0;
        /** @type {bigint} 客户端记录序列号 (64 位无符号整型)，用于 AES-GCM IV 掩码和记录顺序管理 */
        this.clientSeqNum = 0n;
        /** @type {bigint} 服务端单调递增包序列号 (64 位无符号整型) */
        this.serverSeqNum = 0n;
        /** @type {RecordParser} TLS 记录层流解析器 */
        this.recordParser = new RecordParser();
        /** @type {HandshakeParser} TLS 握手层消息解析器 */
        this.handshakeParser = new HandshakeParser();
        /** @type {Map<number, {kp: CryptoKeyPair, pk: Uint8Array}> | null} 本地临时 ECDH 密钥对缓存映射 */
        this.keyPairs = new Map();
        /** @type {Uint8Array[]} 已解密的应用层明文数据包缓存队列 */
        this.packetQueue = [];
        /** @type {Promise<void>} 写入串行化 Promise 任务链，保证异步加解密与发包的绝对时序 */
        this.writeQueue = Promise.resolve();
        /** @type {Uint8Array} BYOB (Bring Your Own Buffer) 读取目标缓冲区 (64KB；仅在底层流支持 BYOB 时使用) */
        this.readBuffer = new Uint8Array(65536);
        /** @type {ReadableStreamBYOBReader | null} 底层输入流的 BYOB 读取器 */
        this.reader = null;
        /** @type {WritableStreamDefaultWriter | null} 底层输出流的写入器 */
        this.writer = null;
        /** @type {boolean} 是否发生不可恢复的致命错误 */
        this.failed = false;
        /** @type {boolean} 连接是否已彻底关闭 */
        this.closed = false;
        /** @type {boolean} 是否正处于优雅关闭挥手流程中 */
        this.closing = false;
        /** @type {boolean} TLS 握手是否已圆满完成 */
        this.handshakeComplete = false;
        /** @type {Promise<void> | null} close() 方法的单例 Promise，确保多次调用幂等 */
        this.closePromise = null;
        /** @type {boolean} 当前连接是否最终协商为 TLS 1.3 协议 (true: TLS 1.3, false: TLS 1.2) */
        this.isTls13 = false;
        /** @type {number | null} 服务端选定的密码套件编号 (如 0x1301) */
        this.cipherSuite = null;
        /** @type {{keyLen: number, ivLen: number, hash: ("SHA-256"|"SHA-384"), tls13: boolean} | null} 当前套件的密码学配置 */
        this.cipherConfig = null;
        /** @type {Uint8Array | null} 服务端返回的 32 字节 ServerRandom */
        this.serverRandom = null;
        // --- TLS 1.3 密钥衍生状态 ---
        /** @type {Uint8Array | null} TLS 1.3 Handshake Secret */
        this.handshakeSecret = null;
        /** @type {CryptoKey | null} 客户端握手加密密钥 */
        this.clientHandshakeKey = null;
        /** @type {Uint8Array | null} TLS 1.3 客户端/服务端应用流量 Secret (用于 KeyUpdate) */
        this.clientAppSecret = null;
        this.serverAppSecret = null;
        /** @type {Uint8Array | null} 客户端握手基础 IV */
        this.clientHandshakeIv = null;
        /** @type {CryptoKey | null} 服务端握手解密密钥 */
        this.serverHandshakeKey = null;
        /** @type {Uint8Array | null} 服务端握手基础 IV */
        this.serverHandshakeIv = null;
        /** @type {CryptoKey | null} 客户端应用数据加密密钥 (client_application_traffic_key) */
        this.clientAppKey = null;
        /** @type {Uint8Array | null} 客户端应用数据基础 IV (client_application_traffic_iv) */
        this.clientAppIv = null;
        /** @type {CryptoKey | null} 服务端应用数据解密密钥 (server_application_traffic_key) */
        this.serverAppKey = null;
        /** @type {Uint8Array | null} 服务端应用数据基础 IV (server_application_traffic_iv) */
        this.serverAppIv = null;
        // --- TLS 1.2 密钥衍生状态 ---
        /** @type {Uint8Array | null} TLS 1.2 主密钥 (Master Secret, 48 字节) */
        this.masterSecret = null;
        /** @type {CryptoKey | null} 客户端写入加密密钥 (client_write_key) */
        this.clientWriteKey = null;
        /** @type {CryptoKey | null} 服务端写入解密密钥 (server_write_key) */
        this.serverWriteKey = null;
        /** @type {Uint8Array | null} 客户端写入固定 Salt (client_write_IV, 4 字节) */
        this.clientWriteIv = null;
        /** @type {Uint8Array | null} 服务端写入固定 Salt (server_write_IV, 4 字节) */
        this.serverWriteIv = null;
    }
    /**
     * 将原始握手消息追加到转录缓冲区 (Transcript Buffer) 中
     *
     * 根据 TLS 规范，握手消息（不含记录层头部）需要按原始字节顺序累加，
     * 用于计算本地 Finished 和后续密钥派生所需的转录哈希；当前实现不使用它验证对端 Finished。
     *
     * @param {Uint8Array} data - 待追加的原始握手消息（包含 4 字节握手层头部）
     */
    recordHandshake(data) {
        if (this.transcriptLen + data.length > this.transcriptBuffer.length) {
            // 容量不足时动态倍增扩容转录缓冲区
            const newBuffer = new Uint8Array(Math.max(this.transcriptBuffer.length * 2, this.transcriptLen + data.length));
            newBuffer.set(this.transcriptBuffer.subarray(0, this.transcriptLen));
            this.transcriptBuffer = newBuffer;
        }
        this.transcriptBuffer.set(data, this.transcriptLen);
        this.transcriptLen += data.length;
    }
    /**
     * 获取当前完整的握手转录报文快照
     *
     * @returns {Uint8Array} 当前有效转录字节切片
     */
    getTranscript() {
        return this.transcriptBuffer.subarray(0, this.transcriptLen);
    }
    /**
     * 获取并单调递增客户端包序号
     *
     * @returns {bigint} 当前记录分配的 64 位包序号 (0n, 1n, 2n...)
     */
    nextClientSeq() {
        return this.clientSeqNum++;
    }
    /**
     * 获取并单调递增服务端包序号
     *
     * @returns {bigint} 当前待解密记录预期的 64 位包序号
     */
    nextServerSeq() {
        return this.serverSeqNum++;
    }
    /**
     * 遇到不可逆致命错误时的快速失败与资源终结释放
     *
     * 标记失败状态，并尝试关闭底层 socket、取消 reader 和终止 writer；锁的释放由调用方或后续清理流程负责。
     */
    fail() {
        const client = this;
        client.failed = client.closed = true;
        try { client.socket?.close(); } catch {}
        try { client.reader?.cancel(); } catch {}
        try { client.writer?.abort(); } catch {}
    }
    /**
     * 从底层网络流中读取一个数据块（底层流支持 BYOB 时传入预分配缓冲区）
     *
     * 性能要点:
     * 传入 `this.readBuffer` 给 `reader.read()`，减少部分读取结果分配；WHATWG Streams 不保证操作系统级零拷贝，
     * 读取结果随后仍会被复制到 `RecordParser` 的缓冲区。
     *
     * @returns {Promise<ReadableStreamReadResult<Uint8Array>>} 读取结果对象 `{value, done}`
     * @throws {Error} 若底层流返回空值则抛出异常
     */
    async readChunk() {
        const client = this;
        const result = await client.reader.read(client.readBuffer);
        if (!result) throw new Error("Socket read returned null/undefined");
        if (!result.done && result.value) {
            // 重新包装 BYOB 读取结果使用的 ArrayBuffer；解析器接收数据时仍会进行复制
            client.readBuffer = new Uint8Array(result.value.buffer);
        }
        return result;
    }
    /**
     * 记录层循环驱动分发器
     *
     * 持续从底层流中读取数据块送入 RecordParser，一旦解析出一个完整的 TLS 记录帧，
     * 即调用回调函数 `onRecord` 进行处理。当 `onRecord` 返回 truthy 值时结束当前驱动循环。
     *
     * @param {(record: {type: number, version: number, length: number, fragment: Uint8Array}) => Promise<any> | any} onRecord - 记录帧处理回调
     * @returns {Promise<void>}
     * @throws {Error} 若连接提前关闭或异常时抛出错误
     */
    async processRecords(onRecord) {
        const client = this;
        while (true) {
            let record;
            // 优先消耗解析器缓冲区中已积压的完整记录帧
            while ((record = client.recordParser.next())) {
                if (await onRecord(record)) return;
            }
            // 缓冲区不足一个完整帧时，从底层网络流读取更多数据块
            const {value, done} = await client.readChunk();
            if (done) throw new Error("Connection closed during record processing");
            client.recordParser.feed(value);
        }
    }
    /**
     * 更新服务端读取流量密钥并归零接收序列号 (RFC 8446 Section 7.2)
     */
    async updateServerKeys() {
        const hash = this.cipherConfig.hash;
        const hashLen = getHashLength(hash);
        const {keyLen, ivLen} = this.cipherConfig;
        this.serverAppSecret = await hkdfExpandLabel(hash, this.serverAppSecret, "traffic upd", EMPTY_BUFFER, hashLen);
        [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hash, this.serverAppSecret, keyLen, ivLen, "decrypt");
        this.serverSeqNum = 0n; // RFC 8446 规定：新密钥序列号必须重置为 0
    }
    /**
     * 更新客户端写入流量密钥并归零发送序列号
     */
    async updateClientKeys() {
        const hash = this.cipherConfig.hash;
        const hashLen = getHashLength(hash);
        const {keyLen, ivLen} = this.cipherConfig;
        this.clientAppSecret = await hkdfExpandLabel(hash, this.clientAppSecret, "traffic upd", EMPTY_BUFFER, hashLen);
        [this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hash, this.clientAppSecret, keyLen, ivLen, "encrypt");
        this.clientSeqNum = 0n; // 发送序列号重置为 0
    }
    /**
     * 发送 KeyUpdate 握手消息 (0: update_not_requested, 1: update_requested)
     */
    sendKeyUpdate(requestUpdate = 0) {
        const client = this;
        // 增加连接就绪与关闭状态防守：
        if (!client.handshakeComplete || client.failed || client.closing) {
            return Promise.reject(new Error("Socket not ready or closing"));
        }
        const task = client.writeQueue.then(async () => {
            if (client.failed || client.closing) throw new Error("Connection failed or closing");
            const keyUpdateMsg = wrapHandshakeMessage(24, [requestUpdate]);
            const encrypted = await client.encryptTls13(keyUpdateMsg, client.nextClientSeq(), 22);
            await client.writer.write(wrapTlsRecord(23, encrypted));
            await client.updateClientKeys();
        });
        // 增加与 write() 一致的 fail 触发与队列隔离：
        const chained = task.catch((err) => {
            client.fail();
            throw err;
        });
        client.writeQueue = chained.catch(() => {});
        return chained;
    }
    /**
     * 执行 TLS 客户端握手流程 (TLS 1.2 & TLS 1.3 双分支自适应)
     *
     * 握手执行时序总览:
     * 1. 【本地秘钥预生成】: 并发生成 P-256 和 X25519 两套临时公私钥对；
     * 2. 【发送 ClientHello】: 打包双曲线公钥及支持的密码套件，向对端发送 ClientHello；
     * 3. 【接收 ServerHello】: 解析服务端响应，依据 supported_versions 扩展判断进入 TLS 1.3 还是 TLS 1.2 分支；
     *
     * --- TLS 1.3 分支 (RFC 8446 1-RTT 快速握手) ---
     * 4. 基于服务端返回的 key_share 与本地对应私钥计算 ECDH 共享秘密；
     * 5. 按照 HKDF 派生状态机推导 Handshake Secret，并派生 Client/Server 握手流量秘钥；
     * 6. 接收并解密服务端 EncryptedExtensions, Certificate, CertificateVerify, Finished 握手帧；当前实现不验证证书链、签名或 Finished verify_data；
     * 7. 派生 Application Traffic Secret 与应用数据流量秘钥；
     * 8. 发送客户端 Finished 报文，随后将应用数据记录序列号重置为 0；
     *
     * --- TLS 1.2 分支 (RFC 5246 ECDHE 握手，包含记录合并与粘包处理) ---
     * 4. 【优先排空本地缓存】: 提取已积压在 RecordParser 和 HandshakeParser 的握手数据；
     * 5. 接收并解析 ServerCertificate, ServerKeyExchange (提取服务端曲线与公钥), ServerHelloDone；
     * 6. 计算 ECDH Pre-Master Secret；
     * 7. 利用 PRF 算法扩展出 48 字节 Master Secret 及 Key Block (Client/Server AES Key 与 4 字节 Salt)；
     * 8. 【合并尾包写入】: 将 ClientCertificate(若有)、ClientKeyExchange、ChangeCipherSpec 与
     *    加密的 ClientFinished 合并为一次 WritableStream 写入；这不保证 TCP 层的报文原子性；
     * 9. 接收并解密服务端的 ChangeCipherSpec 与 ServerFinished（流式提取，可处理 NewSessionTicket 粘包；不验证 Finished verify_data）；
     *
     * 10. 【状态清理】: 清除部分握手状态的 JavaScript 引用，以便后续垃圾回收；不保证敏感字节被立即零化，转录缓冲区也不会在此处清空。
     *
     * @returns {Promise<void>} 握手成功后 Promise resolve，失败则抛出详细异常
     */
    async handshake() {
        // 【性能优化】: 将 this 缓存为局部变量 client，避免长方法与异步跨帧中反复查找 this
        const client = this;
        // 1. 本地并发生成 P-256 和 X25519 两对临时秘钥，消除串行生成延迟
        const [p256KeyPair, x25519KeyPair] = await Promise.all([
            generateEcdhKeyPair("P-256"),
            generateEcdhKeyPair("X25519")
        ]);
        client.keyPairs = new Map([
            [23, p256KeyPair], // 23: secp256r1
            [29, x25519KeyPair] // 29: X25519
        ]);
        // 获取底层流的 Reader 与 Writer
        client.reader = client.socket.readable.getReader({mode: "byob"});
        client.writer = client.socket.writable.getWriter();
        try {
            // 2. 构造并发送 ClientHello
            const clientHello = buildClientHello(
                client.clientRandom,
                client.serverName,
                {p256: p256KeyPair.pk, x25519: x25519KeyPair.pk},
                {sessionId: client.sessionId}
            );
            client.recordHandshake(clientHello);
            // 按照 RFC 8446 Appendix D.4 规定，为避免古老网络中间盒丢包，
            // 初始未加密握手记录层外层伪装版本号写入 0x0301 (769, 即 TLS 1.0)
            await client.writer.write(wrapTlsRecord(22, clientHello, 769));
            // 3. 读取并解析服务端的 ServerHello
            const serverHello = await client.readServerHello();
            // ----------------------------------------------------------------
            // 分支 A: TLS 1.3 握手流程
            // ----------------------------------------------------------------
            if (serverHello.isTls13) {
                // 校验服务端 key_share 曲线是否匹配本端发送的 Group
                const groupCurve = serverHello.ks?.group === 29 ? "X25519" : serverHello.ks?.group === 23 ? "P-256" : null;
                const localKeyPair = client.keyPairs.get(serverHello.ks?.group);
                if (!groupCurve || !serverHello.ks?.key?.length || !localKeyPair) {
                    throw new Error("Missing or invalid key_share from server");
                }
                const hash = client.cipherConfig.hash;
                const hashLen = getHashLength(hash);
                const {keyLen, ivLen} = client.cipherConfig;
                // 3.1 派生 Early Secret & Handshake Secret (RFC 8446 Section 7.1)
                // Shared Secret (Z) = ECDH(localPrivateKey, serverPublicKey)
                const sharedSecret = await deriveSharedSecret(localKeyPair.kp.privateKey, serverHello.ks.key, groupCurve);
                // Early Secret = HKDF-Extract(salt=0, IKM=0)
                const earlySecret = await hkdfExtract(hash, null, new Uint8Array(hashLen));
                const emptyHash = await hashDigest(hash, EMPTY_BUFFER);
                // Derived Secret = HKDF-Expand-Label(Early Secret, "derived", emptyHash, hashLen)
                const derivedEarlySecret = await hkdfExpandLabel(hash, earlySecret, "derived", emptyHash, hashLen);
                // Handshake Secret = HKDF-Extract(salt=Derived Secret, IKM=Shared Secret)
                client.handshakeSecret = await hkdfExtract(hash, derivedEarlySecret, sharedSecret);
                // 3.2 派生握手阶段流量密钥 (Handshake Traffic Keys)
                const hsTranscriptHash = await hashDigest(hash, client.getTranscript());
                const clientHsSecret = await hkdfExpandLabel(hash, client.handshakeSecret, "c hs traffic", hsTranscriptHash, hashLen);
                const serverHsSecret = await hkdfExpandLabel(hash, client.handshakeSecret, "s hs traffic", hsTranscriptHash, hashLen);
                [client.clientHandshakeKey, client.clientHandshakeIv] = await deriveTrafficKeys(hash, clientHsSecret, keyLen, ivLen, "encrypt");
                [client.serverHandshakeKey, client.serverHandshakeIv] = await deriveTrafficKeys(hash, serverHsSecret, keyLen, ivLen, "decrypt");
                let certRequestReceived = false;
                // 3.3 循环接收并解密服务端后续握手报文 (EncryptedExtensions, Certificate, Finished 等)
                await client.processRecords(async (record) => {
                    // TLS 1.3 中间盒兼容模式下服务端可能发送无意义的 ChangeCipherSpec (20)。
                    // 当前实现也会跳过外层类型为 22 的记录，但这不是 TLS 1.3 明文握手的协议合法性验证。
                    if (record.type === 20 || record.type === 22) return;
                    if (record.type === 21) {
                        if (isUnrecognizedNameAlert(record.fragment)) return;
                        throw new Error("TLS alert received during handshake");
                    }
                    if (record.type !== 23) return; // 只处理已加密的应用数据外壳帧 (23)
                    // 使用服务端握手秘钥解密记录层
                    const decrypted = await aesGcmDecrypt(
                        client.serverHandshakeKey,
                        xorIv(client.serverHandshakeIv, client.nextServerSeq()),
                        record.fragment,
                        createTls13Aad(record.fragment.length)
                    );
                    const {data, type} = unpadTls13Plaintext(decrypted);
                    if (type === 22) { // 真实的内层协议类型为握手协议 (22)
                        client.handshakeParser.feed(data);
                        let hsMsg;
                        while ((hsMsg = client.handshakeParser.next())) {
                            client.recordHandshake(hsMsg.raw);
                            if (hsMsg.type === 13) {
                                certRequestReceived = true; // 服务端要求双向客户端证书认证
                            } else if (hsMsg.type === 20) {
                                return 1;
                            }
                        }
                    }
                });
                // 3.4 派生应用数据流量密钥 (Application Traffic Keys)
                const finishedTranscriptHash = await hashDigest(hash, client.getTranscript());
                const derivedHsSecret = await hkdfExpandLabel(hash, client.handshakeSecret, "derived", emptyHash, hashLen);
                // Master Secret = HKDF-Extract(salt=derivedHsSecret, IKM=0)
                const masterSecret = await hkdfExtract(hash, derivedHsSecret, new Uint8Array(hashLen));
                client.clientAppSecret = await hkdfExpandLabel(hash, masterSecret, "c ap traffic", finishedTranscriptHash, hashLen);
                client.serverAppSecret = await hkdfExpandLabel(hash, masterSecret, "s ap traffic", finishedTranscriptHash, hashLen);
                [client.clientAppKey, client.clientAppIv] = await deriveTrafficKeys(hash, client.clientAppSecret, keyLen, ivLen, "encrypt");
                [client.serverAppKey, client.serverAppIv] = await deriveTrafficKeys(hash, client.serverAppSecret, keyLen, ivLen, "decrypt");
                // 若服务端请求证书，发送空 Certificate 消息（无客户端证书响应）
                let certMessage = EMPTY_BUFFER;
                if (certRequestReceived) {
                    certMessage = wrapHandshakeMessage(11, [0, 0, 0, 0]);
                    client.recordHandshake(certMessage);
                }
                // 3.5 构造并发送客户端 Finished
                const clientFinishedKey = await hkdfExpandLabel(hash, clientHsSecret, "finished", EMPTY_BUFFER, hashLen);
                const clientFinishedVerify = await hmacSign(hash, clientFinishedKey, await hashDigest(hash, client.getTranscript()));
                const clientFinishedMsg = wrapHandshakeMessage(20, clientFinishedVerify);
                client.recordHandshake(clientFinishedMsg);
                // 打包加密发送客户端 Finished（明文末尾追加真实的 ContentType 22）
                const encryptedPayload = concatUint8Arrays(certMessage, clientFinishedMsg, [22]);
                const encryptedRecord = await aesGcmEncrypt(
                    client.clientHandshakeKey,
                    xorIv(client.clientHandshakeIv, client.nextClientSeq()),
                    encryptedPayload,
                    createTls13Aad(encryptedPayload.length + 16)
                );
                await client.writer.write(wrapTlsRecord(23, encryptedRecord));
                // 握手完成，重置记录层序列号，为应用数据传输准备
                client.clientSeqNum = client.serverSeqNum = 0n;
            }
                // ----------------------------------------------------------------
                // 分支 B: TLS 1.2 握手流程 (记录合并与粘包处理)
            // ----------------------------------------------------------------
            else {
                let serverKeyExchange = null;
                let serverHelloDone = false;
                let certRequestReceived = false;
                // 内部辅助函数：处理 TLS 1.2 服务端后续握手报文
                const processHandshake = async (hsMsg) => {
                    client.recordHandshake(hsMsg.raw);
                    if (hsMsg.type === 12) { // 12: ServerKeyExchange
                        // 提取服务端 ECDHE 协商参数: curve_type (1B) || named_curve (2B) || public_key_len (1B) || public_key
                        serverKeyExchange = {
                            namedCurve: readU16BE(hsMsg.body, 1),
                            serverPublicKey: hsMsg.body.subarray(4, 4 + hsMsg.body[3])
                        };
                    } else if (hsMsg.type === 14) { // 14: ServerHelloDone
                        serverHelloDone = true;
                        return 1;
                    } else if (hsMsg.type === 13) { // 13: CertificateRequest
                        certRequestReceived = true;
                    }
                };
                // 【关键修复 1】: 优先排空本地已经接收到的握手层及记录层数据缓存。
                // 若服务端早将 ServerHelloDone 连同前面的报文一次性到达，但记录仍在 RecordParser 中，
                // 直接走 processRecords 可能无谓地等待后续网络数据。
                let done = false;
                let pendingMsg;
                while ((pendingMsg = client.handshakeParser.next())) {
                    if (await processHandshake(pendingMsg)) {
                        done = true;
                        break;
                    }
                }
                if (!done) {
                    let record;
                    while ((record = client.recordParser.next())) {
                        if (record.type === 22) {
                            client.handshakeParser.feed(record.fragment);
                            while ((pendingMsg = client.handshakeParser.next())) {
                                if (await processHandshake(pendingMsg)) {
                                    done = true;
                                    break;
                                }
                            }
                            if (done) break;
                        }
                    }
                }
                // 缓冲区未完整包含 ServerHelloDone 时，才启动持续网络流驱动
                if (!done) {
                    await client.processRecords(async (record) => {
                        if (record.type === 21) {
                            if (isUnrecognizedNameAlert(record.fragment)) return;
                            throw new Error("TLS alert received");
                        }
                        // 在 ServerHelloDone 之前收到 ChangeCipherSpec (20) 不符合本实现的握手顺序，
                        // 因此拒绝；单凭该消息不能判断服务端一定在尝试缩略会话恢复。
                        if (record.type === 20) {
                            throw new Error("Server attempted unexpected session resumption (abbreviated handshake), which is unsupported");
                        }
                        if (record.type === 22) {
                            client.handshakeParser.feed(record.fragment);
                            let m;
                            while ((m = client.handshakeParser.next())) {
                                if (await processHandshake(m)) return 1;
                            }
                        }
                    });
                }
                if (!serverHelloDone || !serverKeyExchange) {
                    throw new Error("TLS 1.2 handshake failed: missing ServerKeyExchange or ServerHelloDone");
                }
                const namedCurve = serverKeyExchange.namedCurve === 29 ? "X25519" : serverKeyExchange.namedCurve === 23 ? "P-256" : null;
                const localKeyPair = client.keyPairs.get(serverKeyExchange.namedCurve);
                if (!namedCurve || !localKeyPair) {
                    throw new Error("Unsupported curve in ServerKeyExchange");
                }
                // 若收到服务端证书请求，准备空证书报文（准备合并发送）
                let clientCertRecord = EMPTY_BUFFER;
                if (certRequestReceived) {
                    const emptyCert = wrapHandshakeMessage(11, [0, 0, 0]);
                    client.recordHandshake(emptyCert);
                    clientCertRecord = wrapTlsRecord(22, emptyCert);
                }
                // 计算 ECDH 预主密钥 (Pre-Master Secret)
                const preMasterSecret = await deriveSharedSecret(localKeyPair.kp.privateKey, serverKeyExchange.serverPublicKey, namedCurve);
                // 构造 ClientKeyExchange 消息并发送本端公钥
                const clientKeyExchangeMsg = wrapHandshakeMessage(16, concatUint8Arrays([localKeyPair.pk.length], localKeyPair.pk));
                client.recordHandshake(clientKeyExchangeMsg);
                // PRF 派生 Master Secret (48 字节) (RFC 5246 Section 8.1)
                // master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]
                const hash = client.cipherConfig.hash;
                client.masterSecret = await prfTls12(
                    preMasterSecret,
                    "master secret",
                    concatUint8Arrays(client.clientRandom, client.serverRandom),
                    48,
                    hash
                );
                // PRF 派生密钥块 Key Block (RFC 5246 Section 6.3)
                // key_block = PRF(master_secret, "key expansion", ServerHello.random + ClientHello.random)
                // AES-GCM 不需要 MAC Key，只包含: client_write_key, server_write_key, client_write_IV (salt), server_write_IV (salt)
                const {keyLen, ivLen} = client.cipherConfig;
                const keyBlock = await prfTls12(
                    client.masterSecret,
                    "key expansion",
                    concatUint8Arrays(client.serverRandom, client.clientRandom),
                    2 * keyLen + 2 * ivLen,
                    hash
                );
                // 分割密钥块
                [client.clientWriteKey, client.serverWriteKey] = await Promise.all([
                    importAesGcmKey(keyBlock.subarray(0, keyLen), "encrypt"),
                    importAesGcmKey(keyBlock.subarray(keyLen, 2 * keyLen), "decrypt")
                ]);
                client.clientWriteIv = keyBlock.subarray(2 * keyLen, 2 * keyLen + ivLen);
                client.serverWriteIv = keyBlock.subarray(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
                // 计算并加密客户端 Finished (12 字节校验值)
                const clientFinishedVerify = await prfTls12(
                    client.masterSecret,
                    "client finished",
                    await hashDigest(hash, client.getTranscript()),
                    12,
                    hash
                );
                const clientFinishedMsg = wrapHandshakeMessage(20, clientFinishedVerify);
                client.recordHandshake(clientFinishedMsg);
                const encryptedClientFinished = await client.encryptTls12(clientFinishedMsg, 22);
                // 将 ClientCertificate(若有)、ClientKeyExchange、ChangeCipherSpec、ClientFinished
                // 四个记录合并为一次 writer.write，减少 WritableStream 写调用；不保证 TCP 层原子性。
                await client.writer.write(concatUint8Arrays(
                    clientCertRecord,
                    wrapTlsRecord(22, clientKeyExchangeMsg),
                    wrapTlsRecord(20, [1]), // ChangeCipherSpec: 0x01
                    wrapTlsRecord(22, encryptedClientFinished)
                ));
                // 等待服务端的 ChangeCipherSpec 和 Finished
                let ccsReceived = false;
                await client.processRecords(async (record) => {
                    if (record.type === 21) {
                        if (isUnrecognizedNameAlert(record.fragment)) return;
                        throw new Error("TLS alert received");
                    }
                    if (record.type === 20) {
                        ccsReceived = true;
                        return;
                    }
                    if (record.type === 22 && ccsReceived) {
                        // 将解密后的明文送入 handshakeParser，处理 NewSessionTicket (Type 4) 与
                        // Finished (Type 20) 粘包在同一加密帧中的情形；这里只检查消息类型，不验证 verify_data。
                        const decrypted = await client.decryptTls12(record.fragment, 22);
                        client.handshakeParser.feed(decrypted);
                        let hsMsg;
                        while ((hsMsg = client.handshakeParser.next())) {
                            if (hsMsg.type === 20) return 1; // 检测到服务端 Finished (HandshakeType: 20)
                        }
                    }
                });
            }
            // 握手成功：清除部分握手状态引用；JavaScript 不提供此处可调用的密钥销毁或内存零化保证
            client.handshakeComplete = true;
            client.clientRandom = client.sessionId = client.serverRandom = client.masterSecret = client.handshakeSecret = null;
            client.clientHandshakeKey = client.serverHandshakeKey = client.clientHandshakeIv = client.serverHandshakeIv = null;
            client.keyPairs.clear();
            client.keyPairs = null;
        } finally {
            // 若握手未成功完成或已失败，释放 reader/writer 的独占锁
            if (!client.handshakeComplete || client.failed) {
                try { client.reader?.releaseLock(); } catch {}
                try { client.writer?.releaseLock(); } catch {}
            }
        }
    }
    /**
     * 等待并解析服务端的 ServerHello 报文，确认协商的版本和密码套件
     *
     * 结构解析要点:
     * - 解析 ServerRandom (32B)、SessionID 与选定的 CipherSuite；
     * - 遍历解析 ServerHello Extensions；
     * - 检查 supported_versions (43) 扩展：若包含 0x0304 (772)，则判定真实协商版本为 TLS 1.3；否则为 TLS 1.2 (0x0303)；
     * - 若为 TLS 1.3，进一步提取 key_share (51) 扩展中服务端的共享公钥。
     *
     * @returns {Promise<{version: number, sr: Uint8Array, sid: Uint8Array, cs: number, comp: number, sv: number, ks: {group: number, key: Uint8Array}|null, isTls13: boolean}>}
     * @throws {Error} 若服务端选择不支持的套件、TLS 版本或连接意外中断则抛出异常
     */
    async readServerHello() {
        // 【性能优化】: 缓存 this 引用至 client
        const client = this;
        while (true) {
            const {value, done} = await client.readChunk();
            if (done) throw new Error("Connection closed before ServerHello");
            client.recordParser.feed(value);
            let record;
            while ((record = client.recordParser.next())) {
                if (record.type === 21) {
                    if (isUnrecognizedNameAlert(record.fragment)) continue;
                    throw new Error("TLS alert during ServerHello");
                }
                if (record.type === 22) {
                    client.handshakeParser.feed(record.fragment);
                    let hsMsg;
                    while ((hsMsg = client.handshakeParser.next())) {
                        if (hsMsg.type !== 2) continue; // 仅处理 ServerHello (Type 2)
                        client.recordHandshake(hsMsg.raw);
                        let offset = 2; // 跳过 legacy_version (2B)
                        const legacyVersion = readU16BE(hsMsg.body, 0);
                        const serverRandom = hsMsg.body.slice(offset, (offset += 32));
                        const sessionIdLen = hsMsg.body[offset++];
                        const sessionId = hsMsg.body.subarray(offset, (offset += sessionIdLen));
                        const cipherSuite = readU16BE(hsMsg.body, offset);
                        offset += 2;
                        const compressionMethod = hsMsg.body[offset++];
                        let selectedVersion = legacyVersion;
                        let keyShare = null;
                        // 遍历解析 ServerHello 扩展字段
                        if (offset < hsMsg.body.length) {
                            const extensionsEnd = offset + 2 + readU16BE(hsMsg.body, offset);
                            offset += 2;
                            while (offset + 4 <= extensionsEnd) {
                                const extType = readU16BE(hsMsg.body, offset);
                                const extLen = readU16BE(hsMsg.body, offset + 2);
                                const extData = hsMsg.body.subarray((offset += 4), (offset += extLen));
                                if (extType === 43 && extLen >= 2) {
                                    // supported_versions (43): 获取真实协商的 TLS 版本
                                    selectedVersion = readU16BE(extData, 0);
                                } else if (extType === 51 && extLen >= 2) {
                                    // key_share (51): 获取服务端选择的 Group 与公钥
                                    keyShare = {
                                        group: readU16BE(extData, 0),
                                        key: extLen >= 4 ? extData.subarray(4, 4 + readU16BE(extData, 2)) : EMPTY_BUFFER
                                    };
                                }
                            }
                        }
                        const isTls13 = selectedVersion === 772; // 0x0304 = TLS 1.3
                        const isSha384 = cipherSuite === 4866 || cipherSuite === 49200 || cipherSuite === 49196;
                        // 校验套件与版本是否在本实现支持范围内；这不是完整的降级攻击防护。
                        if (
                            (!isSha384 && cipherSuite !== 4865 && cipherSuite !== 49199 && cipherSuite !== 49195) ||
                            compressionMethod !== 0 ||
                            (cipherSuite < 49000) !== isTls13 ||
                            (!isTls13 && selectedVersion !== 771)
                        ) {
                            throw new Error("Invalid or unsupported cipher suite / TLS version in ServerHello");
                        }
                        client.serverRandom = serverRandom;
                        client.cipherSuite = cipherSuite;
                        client.cipherConfig = {
                            keyLen: isSha384 ? 32 : 16,
                            ivLen: isTls13 ? 12 : 4,
                            hash: isSha384 ? "SHA-384" : "SHA-256",
                            tls13: isTls13
                        };
                        client.isTls13 = isTls13;
                        return {
                            version: legacyVersion,
                            sr: serverRandom,
                            sid: sessionId,
                            cs: cipherSuite,
                            comp: compressionMethod,
                            sv: selectedVersion,
                            ks: keyShare,
                            isTls13
                        };
                    }
                }
            }
        }
    }
    /**
     * TLS 1.2 AES-GCM 数据帧加密 (RFC 5288 / RFC 5246)
     *
     * 结构与规范:
     * - 报文负载格式: `[ExplicitNonce (8 字节)] || Ciphertext || AuthTag (16 字节)`
     * - 12 字节完整 Nonce 构成: `clientWriteIv (4 字节隐式 salt) || explicitNonce (8 字节显式序号)`
     * - 13 字节 AAD 构成: `seq_num (8B) || contentType (1B) || 0x0303 (2B) || plaintext_length (2B)`
     *
     * @param {Uint8Array} plaintext - 待加密的明文数据
     * @param {number} contentType - 协议类型 (22: Handshake, 23: Application Data)
     * @param {bigint} [seqNum=this.nextClientSeq()] - 64 位包序列号
     * @returns {Promise<Uint8Array>} 包含 8 字节显式 Nonce 的密文数据
     */
    async encryptTls12(plaintext, contentType, seqNum = this.nextClientSeq()) {
        // 【性能优化】: 复用快速 u64ToBytesBE 构造 8 字节显式 Nonce，消除内联构造开销
        const explicitNonce = u64ToBytesBE(seqNum);
        const iv = concatUint8Arrays(this.clientWriteIv, explicitNonce);
        const aad = concatBytes(explicitNonce, contentType, 3, 3, u16ToBytes(plaintext.length));
        const encrypted = await aesGcmEncrypt(this.clientWriteKey, iv, plaintext, aad);
        return concatUint8Arrays(explicitNonce, encrypted);
    }
    /**
     * TLS 1.2 AES-GCM 数据帧解密
     *
     * @param {Uint8Array} recordFragment - 记录层承载的密文片段: `[ExplicitNonce (8B)] || Ciphertext || Tag (16B)`
     * @param {number} contentType - 记录层协议类型
     * @param {bigint} [seqNum=this.nextServerSeq()] - 预期对应的服务端 64 位包序号
     * @returns {Promise<Uint8Array>} 解密校验后的明文数据
     */
    async decryptTls12(recordFragment, contentType, seqNum = this.nextServerSeq()) {
        // 【性能优化】: 复用快速 u64ToBytesBE 构造 8 字节序列号
        const seqBytes = u64ToBytesBE(seqNum);
        const explicitNonce = recordFragment.subarray(0, 8);
        const ciphertext = recordFragment.subarray(8);
        const iv = concatUint8Arrays(this.serverWriteIv, explicitNonce);
        const aad = concatBytes(seqBytes, contentType, 3, 3, u16ToBytes(ciphertext.length - 16));
        return aesGcmDecrypt(this.serverWriteKey, iv, ciphertext, aad);
    }
    /**
     * TLS 1.3 应用数据加密 (RFC 8446 Section 5.2)
     *
     * 规范与流程:
     * 1. 构造 TLSInnerPlaintext: `plaintext || contentType (1B)` (无额外 0 填充)；
     * 2. Nonce 计算: `xorIv(clientAppIv, seqNum)`；
     * 3. AAD 计算: `createTls13Aad(innerPlaintext.length + 16)`；
     * 4. AES-GCM 加密输出密文与 Tag。
     *
     * @param {Uint8Array} plaintext - 待发送的应用层明文
     * @param {bigint} [seqNum=this.nextClientSeq()] - 64 位客户端单调包序号
     * @param {number} [contentType=23] - 真实内容类型 (默认 23: Application Data)
     * @returns {Promise<Uint8Array>} 加密后的密文片段 (Ciphertext + 16B Tag)
     */
    async encryptTls13(plaintext, seqNum = this.nextClientSeq(), contentType = 23) {
        const innerPlaintext = new Uint8Array(plaintext.length + 1);
        innerPlaintext.set(plaintext);
        innerPlaintext[plaintext.length] = contentType;
        const iv = xorIv(this.clientAppIv, seqNum);
        const aad = createTls13Aad(innerPlaintext.length + 16);
        return aesGcmEncrypt(this.clientAppKey, iv, innerPlaintext, aad);
    }
    /**
     * TLS 1.3 应用数据解密
     *
     * @param {Uint8Array} ciphertext - 密文片段 (包含末尾 16B Tag)
     * @param {bigint} [seqNum=this.nextServerSeq()] - 预期服务端 64 位包序号
     * @param {CryptoKey} [key=this.serverAppKey] - 解密使用的 AES-GCM 密钥
     * @param {Uint8Array} [iv=this.serverAppIv] - 基础 IV
     * @returns {Promise<{data: Uint8Array, type: number}>} 解密并剥离 Padding 后的明文数据及真实 ContentType
     */
    async decryptTls13(ciphertext, seqNum = this.nextServerSeq(), key = this.serverAppKey, iv = this.serverAppIv) {
        const decrypted = await aesGcmDecrypt(key, xorIv(iv, seqNum), ciphertext, createTls13Aad(ciphertext.length));
        return unpadTls13Plaintext(decrypted);
    }
    /**
     * 向对端发送应用层明文数据
     *
     * 高性能与安全性实现策略:
     * 1. 【输入副本】: Uint8Array 输入会立即执行 `slice()`；ArrayBuffer 输入通过 `new Uint8Array()` 创建视图，
     *    因此调用方仍需保证其底层 ArrayBuffer 在异步写入完成前不被修改；
     * 2. 【RFC 标准分片】: 大数据自动按 RFC 规定的 16KB (16384B) 最大明文帧长度切片；
     * 3. 【流水线并发加密】: 8 块一组并行触发 `crypto.subtle.encrypt`，实际吞吐取决于运行时实现；
     * 4. 【时序串行保障】: 基于 `writeQueue` 严格将异步加密任务串行排队发射到底层 Socket。
     *
     * @param {Uint8Array | ArrayBuffer | ArrayLike<number>} data - 待发送的应用层明文数据
     * @returns {Promise<void>} 写入成功完成时 resolve
     * @throws {Error} 连接未就绪、连接失败或连接关闭时抛出异常
     */
    write(data) {
        // 【性能优化】: 缓存 this 引用至 client
        const client = this;
        if (!client.handshakeComplete || client.failed || client.closing) {
            return Promise.reject(new Error("Socket not ready or closing"));
        }
        // ======================== 输入生命周期约束 ========================
        // 1. Uint8Array 输入生成独立副本；ArrayBuffer 输入在这里仅创建视图
        const payload = data instanceof Uint8Array ? data.slice() : new Uint8Array(data);
        // 2. 空包保护：避免向网络发送无意义的空记录层帧
        if (!payload.length) return Promise.resolve();
        // ============================================================
        const task = client.writeQueue.then(async () => {
            if (client.failed || client.closing) throw new Error("Connection failed or closing");
            const MAX_FRAGMENT_LEN = 16384; // TLS 标准最大明文片大小 (16KB)
            // 小包路径: 单帧直发，最小化调度开销
            if (payload.length <= MAX_FRAGMENT_LEN) {
                const encrypted = client.isTls13
                    ? await client.encryptTls13(payload)
                    : await client.encryptTls12(payload, 23);
                return client.writer.write(wrapTlsRecord(23, encrypted));
            }
            // 大包流水线路径: 按 16KB 分片，8 块一组并发加密流水线
            for (let offset = 0; offset < payload.length;) {
                const chunkPromises = [];
                for (let i = 0; i < 8 && offset < payload.length; i++, offset += MAX_FRAGMENT_LEN) {
                    const chunk = payload.subarray(offset, Math.min(offset + MAX_FRAGMENT_LEN, payload.length));
                    const seq = client.nextClientSeq();
                    const recordPromise = (
                        client.isTls13
                            ? client.encryptTls13(chunk, seq)
                            : client.encryptTls12(chunk, 23, seq)
                    ).then((enc) => wrapTlsRecord(23, enc));
                    chunkPromises.push(recordPromise);
                }
                const records = await Promise.all(chunkPromises);
                // 批量合并密文帧，单次调用底层 Stream 写入，减少写调用次数
                await client.writer.write(concatUint8Arrays(...records));
            }
        });
        const chained = task.catch((err) => {
            client.fail();
            throw err;
        });
        client.writeQueue = chained.catch(() => {});
        return chained;
    }
    /**
     * 读取对端解密后的应用层数据
     *
     * 批处理读取与容错解密设计:
     * 1. 优先消费已解密数据队列 `packetQueue`；
     * 2. 一次性从 RecordParser 提取最多 8 个记录帧；
     * 3. 执行批量并发解密 (`Promise.all`)，若解密失败直接报错并终止连接；
     * 4. 分发当前实现支持的 Alert 和应用数据记录；不提供 TLS 1.3 renegotiation 处理。
     *
     * @returns {Promise<Uint8Array | null>} 返回解密后的明文数据切片，若连接正常对端关闭则返回 null
     * @throws {Error} 握手未完成、校验失败或遭遇致命 Alert 时抛出异常
     */
    read() {
        // 【性能优化】: 缓存 this 引用至 client，避免异步闭包跨越 microtask 重复查找 this
        const client = this;
        if (client.failed || !client.handshakeComplete) {
            return Promise.reject(new Error("Connection failed or handshake not complete"));
        }
        return (async () => {
            while (true) {
                // 1. 若本地队列已有解密好的数据，直接返回
                if (client.packetQueue.length) {
                    return client.packetQueue.length === 1
                        ? client.packetQueue.pop()
                        : concatUint8Arrays(...client.packetQueue.splice(0));
                }
                if (client.closed) return null;
                // 2. 批量提取最多 8 个 TLS 记录帧并发批量解密
                const batch = [];
                for (let record; batch.length < 8 && (record = client.recordParser.next());) {
                    if (!(client.isTls13 ? record.type === 20 : ![21, 22, 23].includes(record.type))) {
                        if (client.isTls13 && record.type !== 23) throw new Error("Unexpected record type in TLS 1.3");
                        batch.push(record);
                    }
                }
                if (batch.length) {
                    if (client.isTls13) {
                        const startSeq = client.serverSeqNum;
                        let decryptedBatch;
                        try {
                            decryptedBatch = await Promise.all(
                                batch.map((r, idx) => client.decryptTls13(r.fragment, startSeq + BigInt(idx), client.serverAppKey, client.serverAppIv))
                            );
                        } catch {}
                        if (decryptedBatch) {
                            client.serverSeqNum = startSeq + BigInt(decryptedBatch.length);
                            for (const item of decryptedBatch) await client.processTls13Record(item);
                        } else {
                            // 降级逐包解密：可在此处精准捕获 KeyUpdate 并无缝切换密钥解密下一包
                            for (let i = 0; i < batch.length; i++) {
                                const item = await client.decryptTls13(batch[i].fragment, client.serverSeqNum++);
                                await client.processTls13Record(item);
                            }
                        }
                    } else {
                        // TLS 1.2 批量解密
                        const startSeq = client.serverSeqNum;
                        const decryptedBatch = await Promise.all(
                            batch.map((r, idx) => client.decryptTls12(r.fragment, r.type, startSeq + BigInt(idx)))
                        );
                        client.serverSeqNum = startSeq + BigInt(batch.length);
                        for (let i = 0; i < decryptedBatch.length; i++) {
                            const plaintext = decryptedBatch[i];
                            const recType = batch[i].type;
                            if (recType === 23) {
                                client.packetQueue.push(plaintext);
                            } else if (recType === 21) {
                                client.processAlert(plaintext);
                            } else if (recType === 22) {
                                client.handshakeParser.feed(plaintext);
                                while (client.handshakeParser.next()) {}
                            }
                        }
                    }
                    // 检查批处理解密后队列中是否已有可返回的数据
                    if (client.packetQueue.length) {
                        return client.packetQueue.length === 1
                            ? client.packetQueue.pop()
                            : concatUint8Arrays(...client.packetQueue.splice(0));
                    }
                    if (client.closed) return null;
                    continue;
                }
                if (client.closed) return null;
                // 3. 记录帧缓冲区耗尽，从底层流拉取新数据
                const {value, done} = await client.readChunk();
                if (done) return null;
                client.recordParser.feed(value);
            }
        })().catch((err) => {
            client.fail();
            throw err;
        });
    }
    /**
     * 处理 TLS 告警协议 (Alert Protocol) 消息
     *
     * Alert 报文结构 (RFC 5246 / RFC 8446 Section 6):
     * `[Level (1B), Description (1B)]`
     * - Level: 1 (Warning), 2 (Fatal)
     * - Description 0: close_notify (表示对端正常发起连接关闭请求)
     *
     * @param {Uint8Array} alertBytes - 2 字节告警负载
     * @throws {Error} 若接收到 Fatal 致命告警或非正常的 Warning 告警，则抛出异常
     */
    processAlert(alertBytes) {
        this.closed = true;
        if (alertBytes && alertBytes.length >= 2) {
            const level = alertBytes[0];
            const description = alertBytes[1];
            // 致命告警 (Fatal 2) 或除正常断开 (close_notify 0) 外的警告均视为异常
            if (level === 2 || (level === 1 && description !== 0)) {
                this.fail();
                throw new Error(`TLS alert received: level ${level}, description ${description}`);
            }
        }
        this.close();
    }
    /**
     * 处理 TLS 1.3 解密后的内层记录
     *
     * @param {{data: Uint8Array, type: number}} record - 解密后的有效载荷与其真实 ContentType
     */
    async processTls13Record({data, type}) {
        if (type === 23) {
            this.packetQueue.push(data);
        } else if (type === 21) {
            this.processAlert(data);
        } else if (type === 22) {
            // 后握手消息解析
            this.handshakeParser.feed(data);
            let msg;
            while ((msg = this.handshakeParser.next())) {
                if (msg.type === 24) { // 24 = KeyUpdate
                    const requestUpdate = msg.body[0];
                    await this.updateServerKeys();
                    if (requestUpdate === 1) {
                        await this.sendKeyUpdate(0); // 响应服务端的轮换请求
                    }
                }
            }
        }
    }
    /**
     * 优雅挥手关闭 TLS 连接（握手完成且连接未失败时尝试发送 close_notify Alert）
     *
     * 规范要求 (RFC 8446 Section 6.1):
     * 在已完成握手且仍可写入时，断开传输前应向对端加密发送 close_notify (level=1, description=0) 告警，
     * 确保对端能够区分“正常协议层截断”与“恶意网络中间人截断攻击 (Truncation Attack)”。
     *
     * @returns {Promise<void>} 关闭流程结束时 resolve（保证多次调用幂等）
     */
    close() {
        // 【性能优化】: 缓存 this 引用至 client
        const client = this;
        if (client.closePromise) return client.closePromise;
        if (client.failed || !client.handshakeComplete) {
            client.socket?.close();
            return (client.closePromise = Promise.resolve());
        }
        client.closing = true;
        client.writeQueue = client.closePromise = client.writeQueue
            .then(async () => {
                // 构造 close_notify: level=1 (Warning), description=0 (close_notify)
                const closeNotify = new Uint8Array([1, 0]);
                const encrypted = client.isTls13
                    ? await client.encryptTls13(closeNotify, client.nextClientSeq(), 21)
                    : await client.encryptTls12(closeNotify, 21);
                await client.writer.write(wrapTlsRecord(client.isTls13 ? 23 : 21, encrypted));
            })
            .catch(() => {})
            .finally(() => {
                client.closed = true;
                client.socket?.close();
            });
        return client.closePromise;
    }
}
export {TlsClient};
