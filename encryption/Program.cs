using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace encryption
{
    /// <summary>
    /// Aes - Definition Namespace: System.Security.Cryptography
    /// Represents the abstract base class from which all implementations of the Advanced Encryption Standard(AES) must inherit.
    /// </summary>
    public class Crypto
    {
        public static string EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return Convert.ToBase64String(encrypted);
        }
        public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            //you will need to store "textIV" and "textKey" if you want to decrypt this at a later time
            string textIV = getaAESAlgoVector();
            string textKey = getaAESAlgoKey();
            //string textIV = "";
            ///string textKey = "";
            string textEncrypt = "text to encrypt here";
            string encriptedText = Crypto.EncryptStringToBytes_Aes(textEncrypt, Convert.FromBase64String(textKey), Convert.FromBase64String(textIV));
            string roundTrip = Crypto.DecryptStringFromBytes_Aes(Convert.FromBase64String(encriptedText), Convert.FromBase64String(textKey), Convert.FromBase64String(textIV));


            //some options to display outputs for symmetric encryption asymmetric encryption
            printOptions();
            getInput();
        }
        /// <summary>
        /// get a vector to be used for encryption and decryption, the vector must be the same for both ways,
        /// else it will not work properly
        /// </summary>
        /// <returns>string</returns>
        private static string getaAESAlgoVector()
        {
            string vector = "";
            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            using (System.Security.Cryptography.Aes myAes = System.Security.Cryptography.Aes.Create())
            {
                vector = Convert.ToBase64String(myAes.IV);
            }
            return vector;
        }
        /// <summary>
        /// get a encryption key to be used for encryption and decryption, the key must be the same for both ways,
        /// else it will not work properly
        /// </summary>
        /// <returns>string</returns>
        private static string getaAESAlgoKey()
        {
            string key = "";
            // Create a new instance of the Aes
            // class.  This generates a new key and initialization
            // vector (IV).
            using (System.Security.Cryptography.Aes myAes = System.Security.Cryptography.Aes.Create())
            {
                key = Convert.ToBase64String(myAes.Key);
            }
            return key;
        }
        private static void printOptions()
        {
            Console.WriteLine("* Choose the one of the options:");
            Console.WriteLine("1 - for symmetric encryption");
            Console.WriteLine("2 - for asymmetric encryption");
            Console.WriteLine("0 - exit");
        }
        private static void getInput()
        {
            string userInput;
            while ((userInput = Console.ReadLine()) != "0")
            {
                switch (userInput)
                {
                    case "1":
                        Console.WriteLine("* You chose symmetric encryption, insert your text:");
                        OneKeyEncription(inputValidate(Console.ReadLine()));
                        break;
                    case "2":
                        Console.WriteLine("* You chose asymmetric encryption, insert your text:");
                        TwoKeyEncryption(inputValidate(Console.ReadLine()));
                        break;
                    default:
                        Console.WriteLine("* That option doesn't exist, try again.");
                        break;
                }
                printOptions();
            }
        }
        private static string inputValidate(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                Console.WriteLine("* The inserted value is invalid.");
                Console.WriteLine("* Initiate the encryption process again.");
            }
            return input;
        }
        private static void OneKeyEncription(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            using (Aes myAes = Aes.Create())
            {
                //encrypt a string to byte[] with algorithm IV
                byte[] encrypted = EncryptStringToBytes_Aes(text, myAes.Key, myAes.IV);
                Console.WriteLine("* Encrypted Text:");
                Console.WriteLine(Convert.ToBase64String(encrypted));
            }
        }
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }
        private static void TwoKeyEncryption(string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return;
            }
            byte[] dataToEncrypt = new UnicodeEncoding().GetBytes(text);
            byte[] encrypted;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //generate encryption key, false exports the public key and true also exports the private key
                RSAParameters publickey = RSA.ExportParameters(false);
                //RSAParameters privatekey = RSA.ExportParameters(true);
                //encryption of the text with public key, DoOAEPPadding is set to true to improve security and prevent partial decryption
                encrypted = RSAEncrypt(dataToEncrypt, publickey, true);
                Console.WriteLine("* Encrypted Text:");
                Console.WriteLine(Convert.ToBase64String(encrypted));
            }
        }
        private static byte[] RSAEncrypt(byte[] DataToEncrypt, RSAParameters RSAKeyInfo, bool DoOAEPPadding)
        {
            byte[] encryptedData;
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //imports the public key generated on the previous function
                RSA.ImportParameters(RSAKeyInfo);
                encryptedData = RSA.Encrypt(DataToEncrypt, DoOAEPPadding);
            }
            return encryptedData;
        }
    }
}