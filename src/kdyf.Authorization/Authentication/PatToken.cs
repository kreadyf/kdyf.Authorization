using System.Security.Cryptography;
using System.Text;

namespace kdyf.Authorization.Authentication
{
    /// <summary>
    /// Generation and hashing of PAT tokens. The only thing persisted is the SHA-256 hash; the
    /// plaintext is shown only once when the token is created. The hashing is identical to the one
    /// <see cref="PatAuthenticationHandler"/> uses, so a token generated here validates there.
    /// </summary>
    public static class PatToken
    {
        /// <summary>SHA-256 (32 bytes) of the token, over its UTF-8 bytes.</summary>
        public static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

        /// <summary>
        /// Generates a random token (base64url, unpadded) and returns its plaintext, a prefix
        /// to identify it in the UI, and its hash to persist.
        /// </summary>
        public static (string Token, string Prefix, byte[] Hash) Create(int byteLength = 32)
        {
            var raw = RandomNumberGenerator.GetBytes(byteLength);
            var token = Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            var prefix = token.Length <= 8 ? token : token[..8];
            return (token, prefix, Hash(token));
        }
    }
}
