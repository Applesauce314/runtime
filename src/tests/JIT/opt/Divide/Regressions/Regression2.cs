// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Generated by Fuzzlyn v1.5 on 2023-02-22 21:24:57
// Run on X64 Windows
// Seed: 15773855565313675298
public class Program
{
    public static sbyte s_3 = 10;
    public static int Main()
    {
        var result = 100;

        for (int vr7 = 0; vr7 < 2; vr7++)
        {
            short vr16 = s_3--;
            short vr19 = s_3--;
            short vr20 = s_3--;
            short vr21 = s_3--;
            short vr22 = s_3--;
            var vr13 = M23();
            if (vr7 == 0 && vr13 != 0)
            {
                result = 0;
            }
            else if (vr7 == 1 && vr13 != -17937)
            {
                result = 0;
            }
        }

        return result;
    }

    public static short M23()
    {
        return (short)((uint)(1L / s_3--) / 37963);
    }
}
