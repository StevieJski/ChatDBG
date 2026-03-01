/*
 * DotnetCrashSample — Minimal .NET program with multiple crash modes
 * for WinDbg + SOS testing with ChatDBG.
 *
 * Build: dotnet build -c Debug
 * Run:   dotnet run -- nullref        → NullReferenceException
 *        dotnet run -- stackoverflow  → StackOverflowException
 *        dotnet run -- async          → Unhandled async Task exception
 *        dotnet run                   → defaults to nullref
 *
 * Debug: cdb DotnetCrashSample.exe nullref
 */

using System;
using System.Threading.Tasks;

namespace DotnetCrash
{
    class Config
    {
        public string Name { get; set; }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "nullref";

            switch (mode)
            {
                case "stackoverflow":
                    CrashStackOverflow();
                    break;
                case "async":
                    CrashAsync().GetAwaiter().GetResult();
                    break;
                case "nullref":
                default:
                    CrashNullRef();
                    break;
            }
        }

        static string ProcessData(string data)
        {
            // This will throw NullReferenceException when data is null
            return data.Trim().ToUpper();
        }

        static void CrashNullRef()
        {
            Console.WriteLine("About to crash with NullReferenceException...");
            string input = null;
            string result = ProcessData(input);
            Console.WriteLine($"Result: {result}");
        }

        static void CrashStackOverflow()
        {
            Console.WriteLine("About to crash with StackOverflowException...");
            RecursiveMethod(0);
        }

        static void RecursiveMethod(int depth)
        {
            // Unbounded recursion — will overflow the stack
            RecursiveMethod(depth + 1);
        }

        static async Task CrashAsync()
        {
            Console.WriteLine("About to crash with async exception...");
            await Task.Run(() =>
            {
                throw new InvalidOperationException("Async task failed unexpectedly.");
            });
        }
    }
}
