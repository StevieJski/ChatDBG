/*
 * dotnet_crash_sample.cs - Minimal .NET program that throws an unhandled
 * NullReferenceException. Used for WinDbg + SOS testing with ChatDBG.
 *
 * Build: dotnet build
 * Run:   dotnet run
 * Debug: cdb dotnet_crash_sample.exe
 */

using System;

namespace DotnetCrash
{
    class Config
    {
        public string Name { get; set; }
    }

    class Program
    {
        static string ProcessData(string data)
        {
            // This will throw NullReferenceException when data is null
            return data.Trim().ToUpper();
        }

        static void Main(string[] args)
        {
            Console.WriteLine("About to crash...");
            string input = null;
            string result = ProcessData(input);
            Console.WriteLine($"Result: {result}");
        }
    }
}
