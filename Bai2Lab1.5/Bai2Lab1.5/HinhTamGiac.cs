using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bai2Lab1._5
{
    class HinhTamGiac : Hinh
    {
        public double a, b, c;

        public override double TinhChuVi() => a + b + c;

        public override double TinhDienTich()
        {
            double p = TinhChuVi() / 2;
            return Math.Sqrt(p * (p - a) * (p - b) * (p - c)); // công thức Heron
        }
    }
}
