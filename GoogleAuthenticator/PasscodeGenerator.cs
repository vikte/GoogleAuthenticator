using System;
using System.Security.Cryptography;

namespace GoogleAuthenticator {
    /// <summary>
    /// Implements HOTP generator specified by RFC 4226.
    /// </summary>
    public class PasscodeGenerator {
        #region Fields
        private const int PASS_CODE_LENGTH = 6;
        private const int INTERVAL = 30;
        private const int ADJECENT_INTERVALS = 1;
        private readonly int PIN_MODULO = (int)Math.Pow(10, PASS_CODE_LENGTH);

        private Func<byte[], byte[]> signer;
        private int codeLength;
        private int intervalPeriod;
        #endregion

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="PasscodeGenerator"/> class.
        /// </summary>
        /// <param name="sha1">The instance of HMAC SHA1.</param>
        public PasscodeGenerator(HMACSHA1 sha1) {
            this.signer = (e) => {
                return sha1.ComputeHash(e);
            };
            this.codeLength = PASS_CODE_LENGTH;
            this.intervalPeriod = INTERVAL;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasscodeGenerator"/> class.
        /// </summary>
        /// <param name="sha1">The instance of HMAC SHA1.</param>
        /// <param name="passCodeLength">Length of the decimal passcode.</param>
        /// <param name="interval">The interval passcode is valid for.</param>
        public PasscodeGenerator(HMACSHA1 sha1, int passCodeLength, int interval) {
            this.codeLength = passCodeLength;
            this.intervalPeriod = interval;
            this.signer = (e) => {
                return sha1.ComputeHash(e);
            };
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="PasscodeGenerator"/> class.
        /// </summary>
        /// <param name="signer">The signer delegate function.</param>
        /// <param name="passCodeLength">Length of the decimal passcode.</param>
        /// <param name="interval">The interval passcode is valid for.</param>
        public PasscodeGenerator(Func<byte[], byte[]> signer, int passCodeLength, int interval) {
            this.signer = signer;
            this.codeLength = passCodeLength;
            this.intervalPeriod = interval;
        }
        #endregion

        #region Private methods
        /// <summary>
        /// Pads the output.
        /// </summary>
        /// <param name="value">The passcode value.</param>
        /// <returns></returns>
        private string PadOutput(int value) {
            string result = value.ToString();
            for (int i = result.Length; i < this.codeLength; i++) {
                result = "0" + result;
            }
            return result;
        }

        /// <summary>
        /// Extracts positive integer value from the input array starting at the given offset.
        /// </summary>
        /// <param name="bytes">The array of bytes.</param>
        /// <param name="start">The starting point of extraction.</param>
        /// <returns></returns>
        private int HashToInt(byte[] bytes, int start) {
            return (((bytes[start] & 0xFF) << 24) | ((bytes[start + 1] & 0xFF) << 16) |
                ((bytes[start + 2] & 0xFF) << 8) | (bytes[start + 3] & 0xFF)
                );
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Generates the timeout code.
        /// </summary>
        /// <returns></returns>
        public string GenerateTimeoutCode() {
            return GenerateResponseCode(this.Clock);
        }

        /// <summary>
        /// Generates the response code.
        /// </summary>
        /// <param name="challange">The challange value.</param>
        /// <returns></returns>
        public string GenerateResponseCode(long challange) {
            byte[] challangeBytes = BitConverter.GetBytes(challange);
            // Must be big endian (according to RFC 4226)
            if (BitConverter.IsLittleEndian)
                // If this runs on little endian system - reverse bytes
                Array.Reverse(challangeBytes, 0, challangeBytes.Length);
            return GenerateResponseCode(challangeBytes);
        }

        /// <summary>
        /// Generates the response code.
        /// </summary>
        /// <param name="challange">The challange value as byte array.</param>
        /// <returns></returns>
        public string GenerateResponseCode(byte[] challange) {
            byte[] hash = this.signer.Invoke(challange);
            int offset = hash[hash.Length - 1] & 0xF;
            int truncatedHash = HashToInt(hash, offset) & 0x7FFFFFFF;
            int pinValue = truncatedHash % PIN_MODULO;
            return PadOutput(pinValue);
        }

        /// <summary>
        /// Verifies the response code.
        /// </summary>
        /// <param name="challange">The challange value.</param>
        /// <param name="response">The response value.</param>
        /// <returns></returns>
        public bool VerifyResponseCode(long challange, string response) {
            string extectedResponse = GenerateResponseCode(challange);
            return extectedResponse.Equals(response);
        }

        /// <summary>
        /// Verifies the timeout code.
        /// </summary>
        /// <param name="timeoutCode">The timeout code.</param>
        /// <returns></returns>
        public bool VerifyTimeoutCode(string timeoutCode) {
            return VerifyTimeoutCode(timeoutCode, ADJECENT_INTERVALS, ADJECENT_INTERVALS);
        }

        /// <summary>
        /// Verifies the timeout code.
        /// </summary>
        /// <param name="timeoutCode">The timeout code.</param>
        /// <param name="pastIntervals">The number of past intervals to check.</param>
        /// <param name="futureIntervals">The number of future intervals to check.</param>
        /// <returns></returns>
        public bool VerifyTimeoutCode(string timeoutCode, int pastIntervals, int futureIntervals) {
            long currentInterval = this.Clock;
            string extectedResponse = GenerateResponseCode(currentInterval);
            if (extectedResponse.Equals(timeoutCode)) {
                return true;
            }
            for (int i = 1; i < pastIntervals; i++) {
                string pastResponse = GenerateResponseCode(currentInterval - i);
                if (pastResponse.Equals(timeoutCode))
                    return true;
            }
            for (int i = 1; i < futureIntervals; i++) {
                string futureResponse = GenerateResponseCode(currentInterval + i);
                if (futureIntervals.Equals(timeoutCode))
                    return true;
            }
            return false;
        }
        #endregion

        #region Properties
        /// <summary>
        /// Gets the interval value in milliseconds starting from the Unix epoch (1970-01-01T00:00:00Z ISO 8601)
        /// </summary>
        /// <value>
        /// Interval the code is valid for (in milliseconds starting from Unix epoch).
        /// </value>
        private long Clock {
            get {
                //Epoch time value
                DateTime epoch = new DateTime(1970, 1, 1);
                //Milliseconds passed Unix epoch.
                long currentTimeMillis = (long)(DateTime.UtcNow - epoch).TotalMilliseconds / 1000;
                return currentTimeMillis / this.intervalPeriod;
            }
            set {
                throw new Exception("No assignment allowed");
            }
        }
        #endregion
    }
}
