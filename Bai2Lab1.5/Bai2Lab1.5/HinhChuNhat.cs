using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bai2Lab1._5
{
    class HinhChuNhat : Hinh
    {
        public double Dai { get; set; }
        public double Rong { get; set; }

        public override double TinhChuVi() => 2 * (Dai + Rong);
        public override double TinhDienTich() => Dai * Rong;
    }
}
