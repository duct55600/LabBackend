using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai9
    {
        
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap so nguyen duong n: ");
            int n = Convert.ToInt32(Console.ReadLine());
            int giaiThua = 1;
            for (int i = 1; i <= n; i++)
            {
                giaiThua *= i;
            }
            Console.WriteLine($"Giai thua cua {n} la: {giaiThua}");
        }
    }
}
