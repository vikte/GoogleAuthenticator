using System;
using System.Security.Cryptography;
using GoogleAuthenticator;

namespace GoogleAuthenticatorTest {
    class Program {
        static void Main(string[] args) {
            Console.Write("Two step verification secret: ");
            string secret = Console.ReadLine();
            //Decode the secret given by Google
            byte[] secretBytes = Base32String.Instance.Decode(secret);
            PasscodeGenerator passGenenerator = new PasscodeGenerator(new HMACSHA1(secretBytes));
            string timeoutCode = passGenenerator.GenerateTimeoutCode();
            if (!passGenenerator.VerifyTimeoutCode(timeoutCode))
                Console.WriteLine("Timeout code couldn't be verified!");
            else
                Console.WriteLine("Timeout code: {0}", timeoutCode);
            Console.ReadLine();
        }
    }
}
