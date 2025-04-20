using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bai2Lab1._5
{
    class HinhVuong : Hinh
    {
        public double Canh { get; set; }

        public override double TinhChuVi() => 4 * Canh;
        public override double TinhDienTich() => Canh * Canh;
    }
    
}
