using System;
using System.IO;

namespace Kuznechik
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Исходное сообщение должно быть в файле input.txt, а ключ в файле key.txt");
            Console.WriteLine("Зашифрованное сообщение будет в файле cipherText.txt");
            Console.WriteLine("Расшифрованное сообщение будет в файле decipheredText.txt");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine("Режимы:");
            Console.WriteLine("1-Простая замена");
            Console.WriteLine("2-Гаммирование");
            Console.WriteLine("3-Гаммирование с обратной связью по выходу");
            Console.WriteLine("4-Простая замена с зацеплением");
            Console.WriteLine("5-Гаммирование с обратной связью по шифртексту");
            Console.WriteLine("6-Выработка имитовставки");
            Console.WriteLine("----------------------------------------------------");
            Console.Write("Выберите режим шифрования: ");
            int i=0;
            while (i<1||i>6)
            {
            i = int.Parse(Console.ReadLine());
            }
            Console.Write("Выберите размер блока: ");
            int size = int.Parse(Console.ReadLine());
            ModesCry m = new ModesCry(i, size);
            if (i == 2||i==4)
            {
                Console.WriteLine("Для шифрования требуется файл cashe.txt с начальным хэшем.");
                Console.Write("Введите параметр s: ");
                int s = int.Parse(Console.ReadLine());
                m.s = s;
                m.IV = File.ReadAllBytes("cashe.txt");
            }
            if (i == 3)
            {
                Console.WriteLine("Для шифрования требуется файл cashe.txt с начальным хэшем.");
                Console.Write("Параметр n равен длине блока. Параметр m равен длине хэша. Введите параметр s: ");
                int s = int.Parse(Console.ReadLine());
                m.IV = File.ReadAllBytes("cashe.txt");
                m.s = s;
            }
            if (i == 5)
            {
                Console.WriteLine("Для шифрования требуется файл cashe.txt с начальным хэшем.");
                Console.Write("Параметр n равен длине блока. Параметр m равен длине хэша. Введите параметр s: ");
                int s = int.Parse(Console.ReadLine());
                m.IV = File.ReadAllBytes("cashe.txt");
                m.s = s;
            }
            if (i == 6)
            {
                Console.Write("Введите параметр s: ");
                int s = int.Parse(Console.ReadLine());
                m.s = s;
            }
            File.WriteAllBytes("cipherText.txt", m.Encrypt());
            if(i!=6)
            File.WriteAllBytes("decipheredText.txt", m.Decrypt());  
        }
    }
}
