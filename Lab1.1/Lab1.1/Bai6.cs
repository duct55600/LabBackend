using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai6
    {
        
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap so: ");
            int number = Convert.ToInt32(Console.ReadLine());
            if (number > 0)
            {
                Console.WriteLine($"{number} la so duong");
            }
            else if (number < 0)
            {
                Console.WriteLine($"{number} la so am");
            }
            else
            {
                Console.WriteLine($"{number} la so khong");
            }
        }
    }
}
