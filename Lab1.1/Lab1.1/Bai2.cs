namespace Lab1._1
{
    internal class Bai2
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Nhap chieu dai:");
            double length = Convert.ToDouble(Console.ReadLine());
            Console.WriteLine("Nhap chieu rong:");
            double width = Convert.ToDouble(Console.ReadLine());
            double area = length * width;
            Console.WriteLine($"Dien tich HCN: {area}");
        }
    }
}
