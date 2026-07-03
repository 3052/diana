# visual studio

1. visualstudio.microsoft.com/downloads
2. tools for visual studio
3. build tools for visual studio
4. continue
5. workloads
6. desktop development with C++
7. individual components
8. compilers, build tools, and runtimes
9. MSVC VS C++ ARM64/ARM64EC build tools
10. install
11. continue
12. close
13. start
14. visual studio
15. developer powershell for VS

~~~
set-location ice_repro\linker\linkrepro
~~~

for `link.rsp` remove one of these:

~~~
"/wbrdcfg:.\Windows.Media.Protection.PlayReady.dll.wbrd"
"/wbrddll:.\warbird.dll"
~~~

then:

~~~
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
Launch-VsDevShell.ps1 -Arch arm64 -HostArch amd64
Get-Command link | Format-List
$env:OBJECT_ROOT = '.'
link '@link.rsp'
~~~

result:

~~~
Windows.Media.Protection.PlayReady.dll
Windows.Media.Protection.PlayReady.pdb
~~~

## history

- <https://security-explorations.com/samples/mspr_leak_screenshot3.png>
- https://reddit.com/r/ReverseEngineering/comments/1dnicyh
- https://seclists.org/fulldisclosure/2024/Jun/7
- https://security-explorations.com/microsoft-warbird-pmp.html

> We also verified that Microsoft Symbol Server didn’t block request for PDB file
> corresponding to Microsoft internal warbird.dll binary (another leak / bug at
> Microsoft end).

https://files.catbox.moe/8iz2qk.pdb

## ICE\_REPRO.zip

- <http://4a.si/dir/ICE_REPRO.zip>
- https://archive.org/details/ice-repro
