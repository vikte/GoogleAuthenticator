using System;
using System.Collections.Generic;
using System.Text;

namespace GoogleAuthenticator {
    /// <summary>
    /// Encodes byte arrays as case-sensitive base32 strings.
    /// </summary>
    public class Base32String {
        #region Fields
        private const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; //RFC 4668/3548
        private static readonly Base32String INSTANCE = new Base32String(ALPHABET);

        private int[] _lookup = null;

        private char[] DIGITS;
        private int MASK;
        private int SHIFT;
        private Dictionary<char, int> CHAR_MAP;

        private const string SEPARATOR = "-";
        #endregion

        #region Singleton and constructors
        /// <summary>
        /// Gets the instance of singleton class.
        /// </summary>
        public static Base32String Instance {
            get {
                return Base32String.INSTANCE;
            }
            private set {

            }
        }
        /// <summary>
        /// Prevents a default instance of the <see cref="Base32String"/> class from being created.
        /// </summary>
        /// <param name="alphabet">The alphabet.</param>
        private Base32String(string alphabet) {
            DIGITS = ALPHABET.ToCharArray();
            MASK = DIGITS.Length - 1;
            _lookup = new int[37] {
        32, 0, 1, 26, 2, 23, 27, 0, 3, 16, 24, 30, 28, 11, 0, 13, 4, 7, 17,
        0, 25, 22, 31, 15, 29, 10, 12, 6, 0, 21, 14, 9, 5, 20, 8, 19, 18
            };
            SHIFT = NumberOfTrailingZeros(DIGITS.Length);
            CHAR_MAP = new Dictionary<char, int>();
            for (int i = 0; i < DIGITS.Length; i++) {
                CHAR_MAP.Add(DIGITS[i], i);
            }
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Encodes the specified byte array to base32 string.
        /// </summary>
        /// <param name="data">The byte array containing data.</param>
        /// <returns></returns>
        public string Encode(byte[] data) {
            return Base32String.Instance.EncodeInternal(data);
        }

        /// <summary>
        /// Decodes base32 encoded string.
        /// </summary>
        /// <param name="encoded">The encoded string.</param>
        /// <returns></returns>
        public byte[] Decode(string encoded) {
            return Base32String.Instance.DecodeInternal(encoded);
        }
        #endregion

        #region Private methods
        /// <summary>
        /// Gets the number the of trailing zeros.
        /// </summary>
        /// <param name="i">The i.</param>
        /// <returns></returns>
        private int NumberOfTrailingZeros(int i) {
            return _lookup[(-i & i) % 37];
        }

        /// <summary>
        /// Decodes base32 encoded string.
        /// </summary>
        /// <param name="encoded">The encoded string.</param>
        /// <returns></returns>
        private byte[] DecodeInternal(string encoded) {
            encoded = encoded.Trim().Replace(SEPARATOR, "").Replace(" ", "");
            encoded = encoded.ToUpper();
            if (encoded.Length == 0)
                return new byte[0];
            int encodedLength = encoded.Length;
            int outLength = encodedLength * SHIFT / 8;
            byte[] result = new byte[outLength];
            int buffer = 0;
            int next = 0;
            int bitsLeft = 0;
            foreach (char c in encoded.ToCharArray()) {
                if (!CHAR_MAP.ContainsKey(c))
                    throw new FormatException("Illegal character: " + c);
                buffer <<= SHIFT;
                buffer |= CHAR_MAP[c] & MASK;
                bitsLeft += SHIFT;
                if (bitsLeft >= 8) {
                    result[next++] = (byte)(buffer >> (bitsLeft - 8));
                    bitsLeft -= 8;
                }
            }
            return result;
        }

        /// <summary>
        /// Encodes the specified byte array to base32 string..
        /// </summary>
        /// <param name="data">The byte array containing data.</param>
        /// <returns></returns>
        private string EncodeInternal(byte[] data) {
            if (data.Length == 0)
                return "";
            if (data.Length >= (1 << 28))
                throw new ArgumentException();

            int outputLength = (data.Length * 8 + SHIFT - 1) / SHIFT;
            StringBuilder result = new StringBuilder(outputLength);

            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;
            while (bitsLeft > 0 || next < data.Length) {
                if (bitsLeft < SHIFT) {
                    if (next < data.Length) {
                        buffer <<= 8;
                        buffer |= (data[next++] & 0xFF);
                        bitsLeft += 8;
                    } else {
                        int pad = SHIFT - bitsLeft;
                        buffer <<= pad;
                        bitsLeft += pad;
                    }
                }
                int index = MASK & (buffer >> (bitsLeft - SHIFT));
                bitsLeft -= SHIFT;
                result.Append(DIGITS[index]);
            }
            return result.ToString();
        }
        #endregion
    }
}
