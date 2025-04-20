using System;
using System.Collections.Generic;
using Bai2Lab1._5;
class Program
{
    static void Main()
    {
        List<Hinh> dsHinh = new List<Hinh>();

        dsHinh.Add(new HinhTron { BanKinh = 3 });
        dsHinh.Add(new HinhVuong { Canh = 4 });
        dsHinh.Add(new HinhChuNhat { Dai = 5, Rong = 2 });
        dsHinh.Add(new HinhTamGiac { a = 3, b = 4, c = 5 });

        double tongChuVi = 0, tongDienTich = 0;
        foreach (var hinh in dsHinh)
        {
            tongChuVi += hinh.TinhChuVi();
            tongDienTich += hinh.TinhDienTich();
        }

        Console.WriteLine($"Tong chu vi các hinh: {tongChuVi:F2}");
        Console.WriteLine($"Tong dien tich các hinh: {tongDienTich:F2}");
    }
}
