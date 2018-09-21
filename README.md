**INSECURE and INEFFICIENT** reference implementation for the [ECVRF](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-02) (all four specified there).
Requires [GMP](https://gmplib.org) and [NTL](https://shoup.net/ntl).  

**!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!**

THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
IT IS ALSO INEFFICIENT AND COBBLED TOGETHER TOO QUICKLY TO BE ANY GOOD!!! 
DO NOT USE IT!!!

It was written as a reference implementation only, in order to generate test vectors.

------------------------------------------------------------------

Compiling notes: if you are having trouble compiling, check what version
of GMP and NTL you have. Mine worked with GMP 6.1.2 and NTL 10.5.0. In particular, earlier versions of the NTL may require you to add a few more `#include`
declarations:

```
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<NTL/ZZ.h>
#include<NTL/ZZ_p.h>
```

Also, conversion from string to `ZZ_p` may not work directly; you may have to convert to `ZZ` first and then to `ZZ_p`.
