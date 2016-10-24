using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace AES_Morgan
{
    class Program
    {
        static void Main(string[] args)
        {
            //variables
            int opcion = 3;
            string fileName;
            string textoPlano;
            string password;
            string textoCifrado;
            string textoDescifrado;
            const string salt = "salt";
            Console.WriteLine("************Hola*********\n");
            while (opcion != 0)
            {
                //Limpiamos la pantalla para que por cada vuelta vacie la consola
                Console.Clear();
                //Mostramos al usuario el menu de opciones
                Console.WriteLine("************Cifrar o descifrar*********\n");
                Console.WriteLine("Pulsa 1 para cifrar.");
                Console.WriteLine("Pulsa 2 para descifrar.");
                Console.WriteLine("Pulsa 0 para cerrar el programa.\n");
                Console.WriteLine("***************************************\n");

                //Leemos la respuesta del usuario
                opcion = Int32.Parse(Console.ReadLine());

                if (opcion == 1)
                {
                    //Mostramos un pequeño texto para ver que haremos 
                    Console.WriteLine("Cifrar\n");

                    //Pedimos el nombre del archivo, hay que poner la extension, en este caso es .txt
                    Console.WriteLine("Entra el nombre del archivo, para cifrarlo.");

                    //Hacemos un try por si no encontramos el archivo o lo hemos escrito mal
                    try
                    {
                        //Leemos la respuesta esperando que sea el nombre del fichero
                        fileName = Console.ReadLine();

                        //Leemos los datos del fichero y los ponemos en una variable
                        textoPlano = File.ReadAllText(fileName);

                        //Pedimos una contraseña 
                        Console.WriteLine("\nIntroduce la contraseña.");

                        //Llamos a un funcion para leer la contraseña y muestre * en vez de las letras
                        password = EntraPassword();                     

                        //Llamamos a la funcion de encriptar y pasamos el texto la contraseña y el salt
                        textoCifrado = Aes.Encrypt(textoPlano, password, salt);

                        //Guardamos el cifrado en el documento
                        File.WriteAllText(fileName, textoCifrado);

                        //Decimos que se ha guardado
                        Console.WriteLine("\nDocumento cifrado y guardado.");

                        //Hasta que no le den a una tecla no saldremos del bucle
                        Console.ReadKey();
                    }
                    catch(Exception e)
                    {
                        //Decimos que ha habido un error en el proceso
                        Console.WriteLine("\nSe a producido un error en el proceso de cifrado.");

                        //Hasta que no le den a una tecla no saldremos del bucle
                        Console.ReadKey();
                    }

                }
                else if (opcion == 2)
                {
                    //Mostramos un pequeño texto para ver que haremos 
                    Console.WriteLine("Descifrar\n");

                    //Pedimos el nombre del archivo, hay que poner la extension, en este caso es .txt
                    Console.WriteLine("Entra el nombre del archivo, para descifrarlo.");

                    //Hacemos un try por si no encontramos el archivo o lo hemos escrito mal
                    try
                    {
                        //Leemos la respuesta esperando que sea el nombre del fichero
                        fileName = Console.ReadLine();

                        //Leemos los datos del fichero y los ponemos en una variable
                        textoPlano = File.ReadAllText(fileName);

                        //Pedimos una contraseña 
                        Console.WriteLine("\nIntroduce la contraseña.");

                        //Llamo a la funcion para leer la contraseña y que muestre *
                        password = EntraPassword();

                        //Llamamos a la funcion de desencriptar y pasamos el texto la contraseña y el salt
                        textoDescifrado = Aes.Decrypt(textoPlano, password, salt);

                        //Guardamos el cifrado en el documento
                        File.WriteAllText(fileName, textoDescifrado);

                        //Decimos que se ha guardado
                        Console.WriteLine("\nDocumento descidrado y guardado.");

                        //Hasta que no le den a una tecla no saldremos del bucle
                        Console.ReadKey();
                    }
                    catch (Exception e)
                    {
                        //Decimos que ha habido un error en el proceso
                        Console.WriteLine("\nSe a producido un error en el proceso de descifrado.");

                        //Hasta que no le den a una tecla no saldremos del bucle
                        Console.ReadKey();
                    }
                }
            }
            
        }

        //Funcion para leer un texto y mostrar en su logar *
        public static string EntraPassword()
        {
            string password = null;
            ConsoleKeyInfo key;
            do
            {
                key = Console.ReadKey(true);

                // Backspace Should Not Work
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else if (key.Key == ConsoleKey.Backspace)
                {
                    Console.Write("\b \b");

                }
            }
            while (key.Key != ConsoleKey.Enter);
            return password;
        }

    }

    class Aes
    {
        //Llamamos a esta funcion para encriptar el archivo
        public static string Encrypt(string message, string pass, string salt)
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            DeriveBytes rgb = new Rfc2898DeriveBytes(pass, Encoding.Unicode.GetBytes(salt), 9);
            byte[] key = rgb.GetBytes(aes.KeySize >> 3);
            byte[] iv = rgb.GetBytes(aes.BlockSize >> 3);
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            ICryptoTransform encryptor = aes.CreateEncryptor();
            byte[] data = Encoding.Unicode.GetBytes(message);
            byte[] dataencrypt = encryptor.TransformFinalBlock(data, 0, data.Length);
            return Convert.ToBase64String(dataencrypt);
        }

        //Llamamos a esta funcion para desincriptar el archivo 
        public static string Decrypt(string message, string pass, string salt)
        {

            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
            DeriveBytes rgb = new Rfc2898DeriveBytes(pass, Encoding.Unicode.GetBytes(salt), 9);
            byte[] key = rgb.GetBytes(aes.KeySize >> 3);
            byte[] iv = rgb.GetBytes(aes.BlockSize >> 3);
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = iv;
            byte[] data = Convert.FromBase64String(message);
            ICryptoTransform decryptor = aes.CreateDecryptor();
            byte[] datadecrypt = decryptor.TransformFinalBlock(data, 0, data.Length);
            return Encoding.Unicode.GetString(datadecrypt);
        }
    }
    


}

