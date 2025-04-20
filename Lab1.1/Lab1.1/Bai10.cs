using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai10
    {
        
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap so: ");
            int number = Convert.ToInt32(Console.ReadLine());
            bool isPrime = true;
            if (number < 2)
            {
                isPrime = false;
            }
            else
            {
                for (int i = 2; i <= Math.Sqrt(number); i++)
                {
                    if (number % i == 0)
                    {
                        isPrime = false;
                        break;
                    }
                }
            }
            if (isPrime)
            {
                Console.WriteLine($"{number} la so nguyen to");
            }
            else
            {
                Console.WriteLine($"{number} khong phai la so nguyen to");
            }
        }
    }
}
