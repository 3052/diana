# ida pro

https://hex-rays.com/ida-pro

delete:

~~~
HKEY_CURRENT_USER\Software\Hex-Rays
~~~

## create c file

1. new
2. `ICE_REPRO\Linker\linkrepro\Windows.Media.Protection.PlayReady.dll`
3. debug information, yes

Full decompilation of the whole database can be requested via File > Produce
file > Create C file… (hotkey Ctrl+F5). This command decompiles selected or all
functions in the database (besides those marked as library functions) and
writes the result to a text file.

https://hex-rays.com/blog/igors-tip-of-the-week-40-decompiler-basics

## savefile

~~~c
auto file = fopen("g1", "wb");
savefile(file, 0, 0x00CD3190, 0x00CD37CC - 0x00CD3190);
~~~
