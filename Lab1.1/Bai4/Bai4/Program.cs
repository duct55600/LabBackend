using System;

class Program
{
    static void Main()
    {
        Console.Write("Nhập số phần tử của mảng: ");
        int n = int.Parse(Console.ReadLine());

        int[] arr = new int[n];
        for (int i = 0; i < n; i++)
        {
            Console.Write($"Nhập phần tử thứ {i + 1}: ");
            arr[i] = int.Parse(Console.ReadLine());
        }

        int? secondMax = TimSoLonThuHai(arr);
        if (secondMax != null)
            Console.WriteLine($" Số lớn thứ hai trong mảng là: {secondMax}");
        else
            Console.WriteLine("Không tìm được số lớn thứ hai (mảng quá ít giá trị phân biệt).");
    }

    static int? TimSoLonThuHai(int[] arr)
    {
        if (arr.Length < 2)
            return null;

        int max = int.MinValue;
        int secondMax = int.MinValue;

        foreach (int num in arr)
        {
            if (num > max)
            {
                secondMax = max;
                max = num;
            }
            else if (num > secondMax && num < max)
            {
                secondMax = num;
            }
        }

        return (secondMax == int.MinValue) ? null : secondMax;
    }
}
