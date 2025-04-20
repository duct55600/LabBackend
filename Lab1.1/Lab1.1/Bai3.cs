using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai3
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap do C:");
            double celsius = Convert.ToDouble(Console.ReadLine());
            double fahrenheit = (celsius * 9 / 5) + 32;
            Console.WriteLine($"Do F: {fahrenheit}");
        }
    }
}
