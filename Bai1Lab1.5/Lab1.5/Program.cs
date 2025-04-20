using System;

class Program
{
    static void Main()
    {
        List<PhanSo> danhSachPhanSo = new List<PhanSo>();
        Console.Write("Nhap so luong phan so: ");
        int n = int.Parse(Console.ReadLine());

        for (int i = 0; i < n; i++)
        {
            Console.WriteLine($"Phan so thu {i + 1}:");
            PhanSo ps = new PhanSo();
            ps.Nhap();
            danhSachPhanSo.Add(ps);
        }

        PhanSo tong = new PhanSo { TuSo = 0, MauSo = 1 };
        foreach (var ps in danhSachPhanSo)
        {
            tong = PhanSo.Cong(tong, ps);
        }

        Console.WriteLine($"Tong cac phan so: {tong}");
    }

}