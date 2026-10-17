// Shamir 秘密共享：privy-io/shamir-secret-sharing（GF(2⁸)，Uint8Array 进出，零依赖）
// split(secret, shares, threshold) / combine(shares)
export { combine as shamirCombine, split as shamirSplit } from 'shamir-secret-sharing'
