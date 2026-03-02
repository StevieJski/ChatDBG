/*
 * DotnetCrashSample — Minimal .NET program with multiple crash/hang modes
 * for WinDbg + SOS testing with ChatDBG.
 *
 * Build: dotnet build -c Debug
 * Run:   dotnet run -- nullref          → NullReferenceException
 *        dotnet run -- stackoverflow    → StackOverflowException
 *        dotnet run -- async            → Unhandled async Task exception
 *        dotnet run -- linkedlist       → Hangs (linked list cycle)
 *        dotnet run -- eventleak        → OOM (event handler leak)
 *        dotnet run -- deadlock         → Hangs (ABBA deadlock)
 *        dotnet run -- dictcorrupt      → Crash/hang (corrupted dictionary)
 *        dotnet run -- finalizerstall   → OOM (blocked finalizer thread)
 *        dotnet run -- lohfrag          → OOM (LOH fragmentation)
 *        dotnet run                     → defaults to nullref
 *
 * Debug: cdb DotnetCrashSample.exe nullref
 */

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.CompilerServices;

namespace DotnetCrash
{
    class Config
    {
        public string Name { get; set; }
    }

    class ListNode
    {
        public int Value;
        public ListNode Next;
    }

    class Subscriber
    {
        public int Id;
        public byte[] Payload;

        public Subscriber(int id)
        {
            Id = id;
            Payload = new byte[1024]; // 1 KB retained per subscriber
        }

        public void OnEvent(object sender, EventArgs e)
        {
            // Handler prevents this Subscriber from being GC'd
        }
    }

    class BlockingFinalizer
    {
        public int Id;
        public byte[] Data;

        public BlockingFinalizer(int id)
        {
            Id = id;
            Data = new byte[64 * 1024]; // 64 KB each
        }

        ~BlockingFinalizer()
        {
            // This blocks the finalizer thread forever
            Thread.Sleep(Timeout.Infinite);
        }
    }

    class Program
    {
#pragma warning disable CS0067 // Event is never raised — intentional for leak scenario
        static event EventHandler LeakedEvent;
#pragma warning restore CS0067
        static readonly object LockA = new object();
        static readonly object LockB = new object();

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
                case "linkedlist":
                    HangLinkedListCycle();
                    break;
                case "eventleak":
                    CrashEventLeak();
                    break;
                case "deadlock":
                    HangDeadlock();
                    break;
                case "dictcorrupt":
                    CrashDictCorrupt();
                    break;
                case "finalizerstall":
                    CrashFinalizerStall();
                    break;
                case "lohfrag":
                    CrashLohFragmentation();
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

        // --- Advanced scenarios requiring JS-based diagnosis ---

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void HangLinkedListCycle()
        {
            Console.WriteLine("Building linked list with cycle...");

            // Build a 20-node singly-linked list
            ListNode head = new ListNode { Value = 0 };
            ListNode current = head;
            ListNode cycleTarget = null;

            for (int i = 1; i < 20; i++)
            {
                current.Next = new ListNode { Value = i };
                current = current.Next;
                if (i == 5)
                    cycleTarget = current; // Remember node[5]
            }

            // Create cycle: tail -> node[5]
            current.Next = cycleTarget;

            // Iterate the list counting nodes — loops forever
            Console.WriteLine("Traversing list (will hang due to cycle)...");
            ListNode walker = head;
            long count = 0;
            while (walker != null)
            {
                count++;
                if (count % 10_000_000 == 0)
                    Console.WriteLine($"Visited {count} nodes...");
                walker = walker.Next;
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void CrashEventLeak()
        {
            Console.WriteLine("Leaking subscribers via static event handler...");

            int i = 0;
            while (true)
            {
                var sub = new Subscriber(i);
                LeakedEvent += sub.OnEvent; // Subscribe but never unsubscribe

                i++;
                if (i % 10_000 == 0)
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    Console.WriteLine($"Subscribers: {i} (GC'd, but all still rooted by event)");
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void HangDeadlock()
        {
            Console.WriteLine("Setting up ABBA deadlock...");

            var barrier = new ManualResetEventSlim(false);
            var firstLockAcquired = new CountdownEvent(2);

            var t1 = new Thread(() =>
            {
                lock (LockA)
                {
                    Console.WriteLine("Thread 1: acquired LockA, waiting for barrier...");
                    firstLockAcquired.Signal();
                    barrier.Wait();
                    Console.WriteLine("Thread 1: waiting for LockB...");
                    lock (LockB)
                    {
                        Console.WriteLine("Thread 1: acquired both locks (should never print)");
                    }
                }
            });
            t1.Name = "Worker-LockA-then-B";

            var t2 = new Thread(() =>
            {
                lock (LockB)
                {
                    Console.WriteLine("Thread 2: acquired LockB, waiting for barrier...");
                    firstLockAcquired.Signal();
                    barrier.Wait();
                    Console.WriteLine("Thread 2: waiting for LockA...");
                    lock (LockA)
                    {
                        Console.WriteLine("Thread 2: acquired both locks (should never print)");
                    }
                }
            });
            t2.Name = "Worker-LockB-then-A";

            t1.Start();
            t2.Start();

            // Wait until both threads have acquired their first lock
            firstLockAcquired.Wait();
            Console.WriteLine("Both threads hold their first lock — releasing barrier...");
            barrier.Set();

            // Main thread joins both — hangs forever
            t1.Join();
            t2.Join();
            Console.WriteLine("Both threads completed (should never print)");
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void CrashDictCorrupt()
        {
            Console.WriteLine("Corrupting Dictionary<int,string> with concurrent writes...");

            var dict = new Dictionary<int, string>();
            var startBarrier = new ManualResetEventSlim(false);

            var t1 = new Thread(() =>
            {
                startBarrier.Wait();
                for (int i = 0; i < 500_000; i++)
                    dict[i] = $"thread1-{i}";
            });
            t1.Name = "DictWriter-1";

            var t2 = new Thread(() =>
            {
                startBarrier.Wait();
                for (int i = 500_000; i < 1_000_000; i++)
                    dict[i] = $"thread2-{i}";
            });
            t2.Name = "DictWriter-2";

            t1.Start();
            t2.Start();
            startBarrier.Set();

            t1.Join();
            t2.Join();

            Console.WriteLine($"Dictionary has {dict.Count} entries. Iterating corrupted dictionary...");

            // Iterating a corrupted dictionary may throw or loop infinitely
            long sum = 0;
            foreach (var kvp in dict)
            {
                sum += kvp.Key;
            }
            Console.WriteLine($"Sum of keys: {sum}");
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void CrashFinalizerStall()
        {
            Console.WriteLine("Blocking the finalizer thread...");

            // Create and drop initial objects to seed the finalizer queue
            for (int i = 0; i < 100; i++)
            {
                var _ = new BlockingFinalizer(i);
            }

            // Force GC so the finalizer thread picks one up and blocks.
            // Do NOT call WaitForPendingFinalizers — it would deadlock here
            // because the finalizer thread blocks immediately on Sleep(Infinite).
            GC.Collect();
            Thread.Sleep(2000); // Give the finalizer thread time to pick up and block

            Console.WriteLine("Finalizer thread should now be blocked. Allocating more...");

            // Keep allocating — objects pile up in finalization queue since
            // the finalizer thread is stuck on Thread.Sleep(Timeout.Infinite)
            int count = 0;
            while (true)
            {
                var _ = new BlockingFinalizer(1000 + count);
                count++;
                if (count % 1000 == 0)
                {
                    GC.Collect();
                    Console.WriteLine($"Allocated and dropped {count} objects (finalizer blocked)...");
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void CrashLohFragmentation()
        {
            Console.WriteLine("Fragmenting the Large Object Heap...");

            var pinned = new List<byte[]>();

            // Phase 1: Create fragmentation pattern on LOH
            // Allocate pairs of 90KB arrays (>85KB = LOH), keep one, drop the other
            for (int round = 0; round < 200; round++)
            {
                byte[] keep = new byte[90 * 1024];   // 90 KB — pinned (kept)
                byte[] drop = new byte[90 * 1024];   // 90 KB — will be freed
                pinned.Add(keep);
                // 'drop' becomes unreachable here — creates gap on LOH

                if (round % 50 == 0)
                {
                    GC.Collect();
                    Console.WriteLine($"Round {round}: pinned={pinned.Count}, creating gaps...");
                }
            }

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            Console.WriteLine($"Fragmentation established. {pinned.Count} pinned arrays on LOH.");
            Console.WriteLine("Attempting increasingly large allocations...");

            // Phase 2: Try to allocate increasingly large arrays on the fragmented LOH
            // These need contiguous space that doesn't exist due to the gaps
            for (int sizeMB = 1; sizeMB <= 1024; sizeMB *= 2)
            {
                int sizeBytes = sizeMB * 1024 * 1024;
                Console.WriteLine($"Trying to allocate {sizeMB} MB on LOH...");
                byte[] big = new byte[sizeBytes];
                big[0] = 1; // Touch it to ensure allocation
                Console.WriteLine($"  Allocated {sizeMB} MB successfully.");
            }

            // Phase 3: Try a smaller allocation that should fit in gaps
            Console.WriteLine("Trying 90 KB allocation (should fit in gaps)...");
            byte[] small = new byte[90 * 1024];
            small[0] = 1;
            Console.WriteLine("Small allocation succeeded — confirms fragmentation (gaps exist but large contiguous blocks don't).");
        }
    }
}
