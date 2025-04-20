using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai4
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap so nguyen: ");
            int number = Convert.ToInt32(Console.ReadLine());
            if (number % 2 == 0)
            {
                Console.WriteLine($"{number} la so chan");
            }
            else
            {
                Console.WriteLine($"{number} la so le");
            }
                
        }
    }
}
