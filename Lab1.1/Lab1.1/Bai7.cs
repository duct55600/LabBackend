using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Lab1._1
{
    internal class Bai7
    {
        //Viết chương trình kiểm tra xem một năm nhập vào có phải là năm nhuận hay không. 

        //Năm nhuận là năm chia hết cho 4 nhưng không chia hết cho 100, hoặc chia hết cho 400.
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap nam: ");
            int year = Convert.ToInt32(Console.ReadLine());
            if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))
            {
                Console.WriteLine($"{year} la nam nhuan");
            }
            else
            {
                Console.WriteLine($"{year} khong phai la nam nhuan");
            }
        }
    }
}
