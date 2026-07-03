# panasonic

so in the `.bin` is:

`usr\local\lib\libplayready.so.0`

if you decompile that you see:

```c
int __fastcall dec_ecb(const char *a1, char *s1, int a3, int a4, int a5)
{
  if ( strncmp(s1, "Salted__", 8u) )
```

then you just walk back:

```c
int __fastcall j_dec_ecb(const char *a1, char *s1, int a3, int a4, int a5)
{
  return dec_ecb(a1, s1, a3, a4, a5);
```

again:

```c
v16 = j_dec_ecb(g_pszPhrase, v19, 64, (int)v18, 48);
```

again:

```c
  if ( g_pszAdditionalPhrase && *g_pszAdditionalPhrase )
    return (char *)sprintf(g_pszPhrase, "%s%s", g_pszBasePhrase, g_pszAdditionalPhrase);
  else
    return strcpy(g_pszPhrase, g_pszBasePhrase);
```

again:

```c
char *g_pszBasePhrase = "AsF16eEncr4pt"; // weak
```

again:

```c
char *g_pszAdditionalPhrase = "17mt5581"; // weak
```
