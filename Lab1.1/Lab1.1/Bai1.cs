using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai1
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap ten:");
            string name = Console.ReadLine();
            Console.WriteLine("Nhap tuoi:");
            int age = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine($"Xin chao {name}, ban {age} tuoi");
        }
    }
}
