using System;
using System.Collections.Generic;

class PhanSo
{
    public int TuSo { get; set; }
    public int MauSo { get; set; }

    public void Nhap()
    {
        Console.Write("Nhap tu so: ");
        TuSo = int.Parse(Console.ReadLine());
        Console.Write("Nhap mau so: ");
        MauSo = int.Parse(Console.ReadLine());
    }

    public static PhanSo Cong(PhanSo a, PhanSo b)
    {
        int tu = a.TuSo * b.MauSo + b.TuSo * a.MauSo;
        int mau = a.MauSo * b.MauSo;
        return RutGon(new PhanSo { TuSo = tu, MauSo = mau });
    }

    public static PhanSo RutGon(PhanSo p)
    {
        int ucln = UCLN(p.TuSo, p.MauSo);
        p.TuSo /= ucln;
        p.MauSo /= ucln;
        return p;
    }

    public static int UCLN(int a, int b)
    {
        while (b != 0)
        {
            int temp = b;
            b = a % b;
            a = temp;
        }
        return Math.Abs(a);
    }

    public override string ToString()
    {
        return $"{TuSo}/{MauSo}";
    }
}
