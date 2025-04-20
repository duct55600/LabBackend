using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai5
    {
       static void Main(string[] args)
        {
            Console.WriteLine("Nhap so 1: ");
            int number1 = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("Nhap so 2: ");
            int number2 = Convert.ToInt32(Console.ReadLine());

            int tong = number1 + number2;
            int tich = number1 * number2;

            Console.WriteLine($"Tong {tong}");
            Console.WriteLine($"Tich {tich}");
        }
    }
}
