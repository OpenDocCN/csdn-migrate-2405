# IOT 渗透测试秘籍（三）

> 原文：[`annas-archive.org/md5/897C0CA0A546B8446493C0D8A8275EBA`](https://annas-archive.org/md5/897C0CA0A546B8446493C0D8A8275EBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：固件安全最佳实践

在本章中，我们将涵盖以下内容：

+   防止内存损坏漏洞

+   防止注入攻击

+   保护固件更新

+   保护敏感信息

+   加固嵌入式框架

+   保护第三方代码和组件

# 介绍

嵌入式软件是被认为是物联网的核心，尽管嵌入式应用安全通常不被视为嵌入式开发人员和物联网设备制造商的高优先级。这可能是由于缺乏安全编码知识或团队代码库之外的其他挑战。开发人员面临的其他挑战可能包括但不限于**原始设计制造商**（ODM）供应链、有限的内存、小堆栈以及安全地向端点推送固件更新的挑战。本章提供了开发人员可以在嵌入式固件应用中采用的实用最佳实践指南。根据 OWASP 的嵌入式应用安全项目（[`www.owasp.org/index.php/OWASP_Embedded_Application_Security`](https://www.owasp.org/index.php/OWASP_Embedded_Application_Security)），嵌入式最佳实践包括：

+   缓冲区和堆栈溢出保护

+   防止注入攻击

+   保护固件更新

+   保护敏感信息

+   身份管理控制

+   加固嵌入式框架和基于 C 的工具链

+   使用调试代码和接口

+   保护设备通信

+   数据收集和存储的使用

+   保护第三方代码

+   威胁建模

本章将讨论前述的几种最佳实践，主要针对 POSIX 环境，但原则上设计为平台无关。

# 防止内存损坏漏洞

在使用 C 等低级语言时，如果开发人员没有正确检查和验证边界，就有很高的可能性出现内存损坏错误。防止使用已知的危险函数和 API 有助于防止固件内的内存损坏漏洞。例如，已知的不安全 C 函数的非穷尽列表包括：`strcat`、`strcpy`、`sprintf`、`scanf`和`gets`。常见的内存损坏漏洞，如缓冲区溢出或堆溢出，可能包括堆栈或堆的溢出。利用这些特定的内存损坏漏洞的影响因操作系统平台而异。例如，商业 RTOS 平台如 QNX Neutrino 将每个进程及其堆栈与文件系统隔离，最小化攻击面。然而，对于常见的嵌入式 Linux 发行版可能并非如此。在嵌入式 Linux 中，缓冲区溢出可能导致恶意代码的任意执行和对操作系统的修改。在本教程中，我们将展示工具如何帮助检测易受攻击的 C 函数，并提供防止内存损坏漏洞的安全控制和最佳实践。

# 准备工作

对于这个教程，将使用以下工具：

+   **Flawfinder**：Flawfinder 是一个免费的 C/C++静态代码分析工具，报告潜在的安全漏洞。

# 操作方法...

常见的 Linux 实用工具对于搜索 C/C++代码文件非常有帮助。尽管商业上可用的源代码分析工具可以比常见实用工具更好地防止内存损坏漏洞，并且开发人员可以使用 IDE 插件。为了演示目的，我们将展示如何使用 grep 和 flawfinder 搜索代码文件中的预定义函数易受攻击的调用和规则。

1.  要发现不安全的 C 函数，有几种方法可以使用。最简单的形式是使用类似于以下示例的`grep`表达式：

```
$ grep -E '(strcpy|strcat|sprintf|strlen|memcpy|fopen|gets)' code.c

```

这个表达可以调整得更智能一些，或者包装成一个脚本，可以在每次构建时执行，或者按需执行。

1.  或者，可以使用`flawfinder`等免费工具来搜索易受攻击的函数，方法是调用`flawfinder`和代码片段的路径，如以下示例所示：

```
$ flawfinder fuzzgoat.c
Flawfinder version 1.31, (C) 2001-2014 David A. Wheeler.
Number of rules (primarily dangerous function names) in C/C++ ruleset: 169
Examining fuzzgoat.c

FINAL RESULTS:

fuzzgoat.c:1049: [4] (buffer) strcpy:
Does not check for buffer overflows when copying to destination (CWE-120).
Consider using strcpy_s, strncpy, or strlcpy (warning, strncpy is easily misused).
    fuzzgoat.c:368: [2] (buffer) memcpy:
    Does not check for buffer overflows when copying to destination        (CWE-120).
    Make sure destination can always hold the source data.
fuzzgoat.c:401: [2] (buffer) sprintf:
    Does not check for buffer overflows (CWE-120). Use sprintf_s, 
    snprintf, or vsnprintf. Risk is low because the source has a    
    constant maximum length.
    <SNIP>
fuzzgoat.c:1036: [2] (buffer) strcpy:
    Does not check for buffer overflows when copying to destination (CWE-120).
    Consider using strcpy_s, strncpy, or strlcpy (warning, strncpy is 
    easily
    misused). Risk is low because the source is a constant string.
fuzzgoat.c:1041: [2] (buffer) sprintf:
    Does not check for buffer overflows (CWE-120). Use sprintf_s, 
    snprintf, or vsnprintf. Risk is low because the source has a      
    constant maximum length.
fuzzgoat.c:1051: [2] (buffer) strcpy:
    Does not check for buffer overflows when copying to destination (CWE-120).
    Consider using strcpy_s, strncpy, or strlcpy (warning, strncpy is    
    easily misused). Risk is low because the source is a constant     
    string.
ANALYSIS SUMMARY:

Hits = 24
Lines analyzed = 1082 in approximately 0.02 seconds (59316 lines/second)
Physical Source Lines of Code (SLOC) = 765
Hits@level = [0] 0 [1] 0 [2] 23 [3] 0 [4] 1 [5] 0
Hits@level+ = [0+] 24 [1+] 24 [2+] 24 [3+] 1 [4+] 1 [5+] 0
Hits/KSLOC@level+ = [0+] 31.3725 [1+] 31.3725 [2+] 31.3725 [3+] 
1.30719 [4+] 1.30719 [5+] 0
Minimum risk level = 1
Not every hit is necessarily a security vulnerability.
There may be other security vulnerabilities; review your code!
See 'Secure Programming for Linux and Unix HOWTO'
(http://www.dwheeler.com/secure-programs) for more information.

```

1.  在发现正在使用的易受攻击的 C 函数时，必须合并安全替代方案。例如，以下易受攻击的代码使用不安全的`gets()`函数，不检查缓冲区长度：

```
#include <stdio.h> 
int main () { 
    char userid[8]; 
    int allow = 0; 
    printf external link("Enter your userID, please: "); 
    gets(userid);  
    if (grantAccess(userid)) { 
        allow = 1; 
    } 
    if (allow != 0) {  
        privilegedAction(); 
    } 
    return 0; 
} 
```

1.  `userid`可以使用超过`8`个字符的任意数量进行溢出，例如具有自定义执行函数的缓冲区溢出利用（BoF）有效负载。为了减轻缓冲区溢出的影响，可以使用`fgets()`函数作为安全的替代方法。以下示例代码显示了如何安全地使用`fgets()`并正确分配内存：

```
#include <stdio.h> 
#include <stdlib.h> 
#define LENGTH 8 
int main () { 
    char* userid, *nlptr; 
    int allow = 0; 

    userid = malloc(LENGTH * sizeof(*userid)); 
    if (!userid) 
        return EXIT_FAILURE; 
    printf external link("Enter your userid, please: "); 
    fgets(userid,LENGTH, stdin); 
    nlptr = strchr(userid, '\n'); 
    if (nlptr) *nlptr = '\0'; 

    if (grantAccess(userid)) { 
        allow = 1; 
    } 
    if (allow != 0) { 
        priviledgedAction(); 
    } 

    free(userid); 

    return 0; 
} 
```

可以使用相同的缓解措施来使用其他安全替代函数，如`snprintf()`，`strlcpy()`和`strlcat()`。根据操作系统平台的不同，某些安全替代方案可能不可用。重要的是要进行自己的研究，以确定特定架构和平台的安全替代方案。英特尔创建了一个名为`safestringlib`的开源跨平台库，以防止使用这些不安全的禁止函数；使用替代的安全替换函数。有关`safestringlib`的更多详细信息，请访问 GitHub 页面：[`github.com/01org/safestringlib`](https://github.com/01org/safestringlib)。

还可以使用其他内存安全控件来防止内存腐败漏洞，例如以下控件：

+   使用安全编译器标志，如-fPIE，-fstack-protector-all，-Wl，-z，noexecstack，-Wl，-z，noexecheap 等，这些可能取决于您特定的编译器版本。

+   首选包含内存管理单元（MMU）的系统芯片（SoC）和微控制器（MCU）。MMU 将线程和进程隔离，以减少攻击面，如果内存错误被利用。

+   首选包含内存保护单元（MPU）的系统芯片（SoC）和微控制器（MCU）。MPU 强制执行内存的访问规则，并分离进程，同时执行特权规则。

+   如果没有 MMU 或 MPU 可用，可以使用已知位来监视堆栈，以确定堆栈的多少被消耗掉。

+   在放置缓冲区和释放缓冲区位置后，要注意放置什么。

利用地址空间布局随机化（ASLR）和其他堆栈控件的内存漏洞需要攻击者付出大量努力才能利用。尽管在某些情况下仍然可能发生。确保代码具有弹性，并采用深度防御方法，以便将数据放置在内存中有助于嵌入式设备的安全姿态。

# 另请参阅

+   有关更安全的内存管理指南，请参考卡内基梅隆大学的安全 CERT C 编码标准（[`www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard`](https://www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard)）。

+   有关更安全的内存管理指南，请参考卡内基梅隆大学的安全 CERT C++编码标准（[`www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637`](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637)）

# 预防注入攻击

注入攻击是任何 Web 应用程序中最严重的漏洞之一，尤其是在物联网系统中。事实上，自 2010 年以来，注入一直是 OWASP 十大漏洞中排名前两位。有许多类型的注入攻击，如**操作系统**（OS）命令注入、跨站脚本（例如 JavaScript 注入）、SQL 注入、日志注入，以及其他类型的表达式语言注入。在物联网和嵌入式系统中，最常见的注入攻击类型是操作系统命令注入；当应用程序接受不受信任的用户输入并将该值传递以执行 shell 命令而没有输入验证或适当的转义时，以及跨站脚本（XSS）。本文将向您展示如何通过确保所有不受信任的数据和用户输入都经过验证、经过清理，并使用替代安全函数来减轻命令注入攻击。

# 如何做...

当物联网设备运行时，注入攻击的静态和动态测试并不难。固件可以调用`system()`、`exec()`和类似的变体来执行操作系统命令，或者调用从解释语言（如 Lua）运行 OS 调用的外部脚本。命令注入漏洞也可能由缓冲区溢出引起。以下步骤和示例显示了易受命令注入攻击的代码，以及如何减轻命令注入攻击。之后，我们将列出常见的安全控制措施，以防止常见的注入攻击。

1.  以下代码片段调用危险的`system()` C 函数来删除`home`目录中的`.cfg`文件。如果攻击者能够控制该函数，则可以连接后续的 shell 命令来执行未经授权的操作。此外，攻击者可以操纵环境变量来删除任何以`.cfg`结尾的文件：

```
#include <stdlib.h> 

void func(void) { 
  system("rm ~/.cfg"); 
}
```

1.  为了减轻前面的易受攻击的代码，将使用`unlink()`函数而不是`system()`函数。`unlink()`函数不容易受到符号链接和命令注入攻击。`unlink()`函数删除符号链接，不会影响符号链接内容命名的文件或目录。这减少了`unlink()`函数易受符号链接攻击的可能性，但并不能完全阻止符号链接攻击；如果命名目录相同，也可能被删除。`unlink()`函数可以防止命令注入攻击，应该使用类似的上下文函数而不是执行操作系统调用：

```
#include <pwd.h> 
#include <unistd.h> 
#include <string.h> 
#include <stdlib.h> 
#include <stdio.h> 
void func(void) { 
  const char *file_format = "%s/.cfg"; 
  size_t len; 
  char *pathname; 
  struct passwd *pwd; 

  pwd = getpwuid(getuid()); 
  if (pwd == NULL) { 
    /* Handle error */ 
  } 

  len = strlen(pwd->pw_dir) + strlen(file_format) + 1; 
  pathname = (char *)malloc(len); 
  if (NULL == pathname) { 
    /* Handle error */ 
  } 
  int r = snprintf(pathname, len, file_format, pwd->pw_dir); 
  if (r < 0 || r >= len) { 
    /* Handle error */ 
  } 
  if (unlink(pathname) != 0) { 
    /* Handle error */ 
  } 

  free(pathname); 
} 
```

还有其他几种方法可以减轻注入攻击。以下是一些常见的防止注入攻击的最佳实践和控制措施的列表：

+   尽量避免直接调用操作系统调用。

+   如有需要，列出接受的命令并在执行之前验证输入值。

+   为用户驱动的字符串使用数字到命令字符串的查找映射，这些字符串可能会传递给操作系统，例如`{1:ping -c 5}`。

+   对代码库进行静态代码分析，并在使用 OS 命令（如`os.system()`）时发出警报。

+   将所有用户输入视为不受信任，并对返回给用户的数据进行输出编码（例如，`将&转换为&amp`，`将<转换为&lt`，`将>转换为&gt`等）。

+   对于 XSS，使用 HTTP 响应头，如 X-XSS-Protection 和 Content-Security-Policy，并配置适当的指令。

+   确保在生产固件版本中禁用带有命令执行的调试接口（例如，[`example.com/command.php`](http://example.com/command.php)）。

前面提到的控制措施在生产环境中使用固件之前都需要进行测试。在注入攻击中，设备和用户面临被攻击者接管的风险，以及流氓设备。我们在 2017 年看到了物联网 Reaper 和 Persirai 僵尸网络发生的事件。这只是开始。

# 另请参阅

+   有关进一步的注入预防指南和注意事项，请参考 OWASP 的嵌入式应用安全项目（[`www.owasp.org/index.php/OWASP_Embedded_Application_Security`](https://www.owasp.org/index.php/OWASP_Embedded_Application_Security)）和 OWASP XSS（跨站脚本）预防备忘单[`www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet`](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)。

# 保护固件更新

根据行业，只有来自制造商、供应商或企业的授权固件才能刷入设备。为确保这一点，必须在下载固件时使用强大的更新机制，并在适用时，用于更新与第三方软件或库相关的功能。所有固件都应使用加密签名，以便验证文件自开发者创建并签名以来未被修改或篡改。签名和验证过程使用公钥加密，很难在未获得私钥的情况下伪造数字签名（例如 PGP 签名）。使用公钥加密时，必须将其安全存储，并且不暴露给意外的第三方。如果私钥被泄露，软件开发人员必须撤销受损的密钥，并需要使用新密钥重新签署所有先前的固件版本。这已经成为许多物联网产品的问题，用户需要将设备送回或将牵引车辆送到服务商店。保护固件更新的实施因部署物联网设备的行业而异。例如，一些产品可能具有**空中**（**OTA**）更新，而其他产品可能需要通过 USB 手动更新或通过加载新的固件映像的界面进行更新。对于一些普通的消费级物联网设备来说，这可能不是一个大问题，但是如果未经授权的恶意固件加载到连接的车辆或医疗设备上，后果可能是致命的。本文将列出可用于保护固件更新的功能。

# 如何做到…

在为嵌入式物联网设备实施安全更新生态系统时，需要考虑许多变量和因素。某些架构、SoC 或引导加载程序可能无法执行所有必需的操作，以实现弹性固件更新系统。由于实施安全更新系统的复杂性和变化，我们将讨论制造商应该将哪些高级操作纳入其固件更新设计中。为简单起见，我们将以嵌入式 Linux 作为平台，并提供安全更新系统所需的要求。再次强调，并非所有以下要求都可能可行，但对于设备制造商来说，进行尽职调查并了解实施安全更新系统时的风险是很重要的。以下是用于保护固件更新的安全控制和要求。

1.  为引导加载程序实施安全启动或验证启动。

1.  使用安全硬件芯片（例如 TPM、HSM、安全元件）保护安全启动密钥。

1.  确保强大的更新机制利用加密签名的固件图像进行更新功能。

1.  下载和刷写图像后必须进行验证。

1.  确保更新是通过最新的安全 TLS 版本下载的（在撰写本文时，这是 TLS 1.2）：

+   确保更新验证更新服务器的公钥和证书链

1.  包括利用预定时间表的自动固件更新功能：

+   在高度脆弱的用例中强制更新

+   应考虑定期推送更新，以防止强制更新可能造成的问题，特别是对于某些设备，如医疗设备。

1.  确保固件版本清晰显示。

1.  确保固件更新包括包含安全相关漏洞的更改日志。

1.  在固件可用时通过电子邮件、应用程序通知或登录应用程序通知客户新的固件。

1.  确保采用反降级保护（反回滚）机制，以防设备被恢复到一个易受攻击的固件版本。

1.  考虑实施**完整性测量架构**（**IMA**），允许内核通过验证文件的哈希（称为标签）来检查文件是否未被更改。**扩展验证模块**（**EVM**）检查文件属性（包括扩展属性）。

有两种类型的标签可用：

+   不可变和签名

+   简单

1.  考虑实施一个只读的根文件系统，并为需要本地持久性的目录创建一个覆盖层。

一个安全的更新系统严重依赖于公钥密码学来签名和验证固件图像。这需要基础设施和管理来维护设备签名和验证密钥的生命周期。如果密钥被 compromise 或需要更新，应在生产部署之前进行测试，以防止设备变砖。话虽如此，有第三方公司提供**空中固件更新**（**FOTA**）服务，将责任转移到服务提供商。对于像连接车辆这样的产品来说，这可能会很昂贵，制造商需要支付网络数据费用。在选择更新机制时，应考虑一些框架，如 The Update Framework ([`theupdateframework.github.io/`](https://theupdateframework.github.io/))和 Uptane ([`uptane.github.io/`](https://uptane.github.io/))。

# 保护敏感信息

在有限的存储空间和薄利多销的情况下，保护敏感数据对于 IoT 设备来说可能是一个挑战。通常，敏感数据存储在客户端应用程序或设备上，以便 IoT 服务可以在没有互联网连接的情况下运行。在保护设备上的敏感数据时，应遵循一些安全原则。首先，永远不要将秘密硬编码到固件图像中，比如密码、用户名、令牌、私钥或类似的变体。这也包括写入磁盘的敏感数据。这些数据将在提取固件文件系统时对攻击者可见，也会在运行时访问操作系统时对攻击者可见。如果有硬件，如**安全元素**（**SE**）或**可信执行环境**（**TEE**）可用，建议在运行时使用这些功能来存储敏感数据。否则，应评估使用强大的密码学来保护数据，使用服务器端计算来弥补硬件限制。

如果可能，所有明文中的敏感数据应该是短暂的，并且只驻留在易失性内存中。这个配方将为您提供一些数据被不安全使用的场景，以及如何在 IoT 设备中减轻不安全的 C 代码。

# 如何做到...

使用编程示例，我们将展示数据如何被不安全地存储以及如何纠正存储漏洞。

1.  在以下示例中，敏感信息不安全地存储在由`key`引用的动态分配的内存中，然后被复制到动态分配的缓冲区`new_key`中，然后通过调用`free()`最终被处理和释放。由于内存没有被清除，它可能被重新分配到程序的另一个部分，其中存储在`new_key`中的信息可能会被意外泄露：

```
char *key; 

/* Initialize secret */ 

char *new_key; 
size_t size = strlen(key); 
if (size == SIZE_MAX) { 
  /* Handle error */ 
} 

new_key = (char *)malloc(size+1); 
if (!new_key) { 
  /* Handle error */ 
} 
strcpy(new_key, key); 

/* Process new_key... */ 

free(new_key); 
new_key = NULL; 
```

1.  为防止发生信息泄漏，包含敏感信息的动态内存在被释放之前应该进行消毒。消毒通常是通过用`'\0'`字符清除分配的空间来进行的，也被称为清零：

```
char *key; 

/* Initialize secret */ 

char *new_key; 
size_t size = strlen(key); 
if (size == SIZE_MAX) { 
  /* Handle error */ 
} 

/* Use calloc() to zero-out space */ 
new_key = (char *)calloc(size+1, sizeof(char)); 
if (!new_key) { 
  /* Handle error */ 
} 
strcpy(new_key, key); 

/* Process new_key... */ 

/* Sanitize memory  */ 
memset_s(new_key, '\0', size); 
free(new_secret); 
new_key = NULL; 
```

在设备没有硬件安全芯片用于分离操作系统进程和内存位置的情况下，可以使用上述示例。没有硬件安全芯片（例如 TPM 或 SE），或者 ARM 架构的 TEE 环境，对于嵌入式设备来说，安全存储数据是一个挑战。有时开发人员可能会将敏感数据存储在对平台操作系统不可用的不同存储分区中，但这也不是一个安全的存储位置。通常，闪存芯片可以从 PCB 板上取下，并带到离线位置进行审查或数据外泄。

正在创建新的框架和操作系统平台，以帮助解决存储敏感数据的问题。如果使用 ARM Mbed OS，则可以利用名为 uVisor 的设备安全层，通过硬件安全功能限制对内存的访问，从而隔离代码块。尽管 Mbed 还处于起步阶段，但它得到了大型半导体公司的大力支持，并包含了一个平台，不仅包括其操作系统，还包括云服务。

# 另请参阅

+   有关 uVisor 的详细信息可以在以下网站找到：

[`www.mbed.com/en/technologies/security/uvisor/`](https://www.mbed.com/en/technologies/security/uvisor/)

+   uVisor 的示例代码用法可以在 GitHub 存储库中找到，通过以下 URL：

[`github.com/ARMmbed/mbed-os-example-uvisor-number-store`](https://github.com/ARMmbed/mbed-os-example-uvisor-number-store)

+   有关 Mbed OS 的更多信息，请访问以下网址：

[`www.mbed.com`](https://www.mbed.com/)

# 加固嵌入式框架

设计和构建嵌入式固件可能会很复杂，因为它涉及所有的依赖关系和几十年未被触及的混乱 makefile。尽管存在这些常见的复杂性，但建立安全软件的基础始于加固平台和工具链。许多嵌入式 Linux 设备使用包含常见 GNU 实用程序的 BusyBox。对 BusyBox 需要进行某些配置，也需要进行更新。除了 BusyBox，嵌入式框架和工具链应该被修改为只包括在配置固件构建时使用的库和函数。RTOS 系统通常也有 POSIX 实用程序可用，但由 SoC、MCU 和芯片供应商进行配置，他们拥有修改版本的常见实用程序。嵌入式 Linux 构建系统，如 Buildroot、Yocto 等，执行设置和配置工具链环境的任务。删除已知的不安全库和协议，如 Telnet，不仅可以减少固件构建中的攻击入口点，还可以提供一种安全设计的方法来构建软件，以防范潜在的安全威胁。在本教程中，我们将展示如何使用 Buildroot 来选择和取消选择网络服务和配置。

# 准备工作

在本教程中，将使用 Buildroot 来演示加固。

**Buildroot**是通过交叉编译生成嵌入式 Linux 系统的工具。可以通过以下网站下载 Buildroot：

[`buildroot.uclibc.org/download.html`](https://buildroot.uclibc.org/download.html).

# 如何做...

我们将首先使用 Buildroot，并打开其菜单选项进行配置。

1.  下载 Buildroot 后，在 Buildroot 文件夹的根目录中运行以下命令，以显示 Buildroot 的配置选项：

```
    $ make menuconfig
```

根据偏好，还可以使用其他配置用户界面，如`xconfig`和`gconfig`。有关更多详细信息，请查阅 Buildroot 的用户手册：[`buildroot.uclibc.org/downloads/manual/manual.html`](https://buildroot.uclibc.org/downloads/manual/manual.html)。

1.  应该出现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b940eca2-6c98-4eb7-bb84-81d5036264c8.png)

1.  在这里，可以对 Linux 固件映像进行配置。对于我们的目的，我们将向您展示如何选择安全的守护程序和安全的默认设置。

1.  接下来，转到工具链菜单，并启用堆栈保护支持，使用`-fstack-protector-all`构建标志：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/98ad6f32-da38-4355-bcc3-5bf03a4093b2.png)

1.  转到主菜单屏幕，并进入系统配置菜单。选择密码编码，并选择 sha-512：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8429a2f7-cb90-4549-b4c2-af3060a1aeaf.png)

1.  在系统配置页面，我们可以为固件映像创建根密码。在这里，我们希望使用一个长的字母数字密码，就像屏幕截图中显示的那样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/02cc8e17-c5c0-4e6b-a11d-4f31a8229a4b.png)

1.  退出系统配置菜单，转到目标软件包菜单选项。在这里，我们可以指定要包含在固件映像中的工具、库、守护程序和第三方代码。根据设备的不同，可以选择许多选项，所以我们只使用一个示例。以下屏幕截图显示了选择 openssh 而不是 Telnet：

只有在要使用 TLS 时才启用 FTP。对于 Pure-FTPd，这需要通过传递`./configure --with-tls`进行自定义编译。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8d0fd502-8aa7-42d4-9f97-4fb750e13a5e.png)

1.  返回到目标软件包菜单，并选择 Shell 和实用程序子菜单。在这里，确保只选择一个 shell 解释器，以减少攻击面：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2ee86680-4a80-4eb3-9ea8-418ed861e5cb.png)

选择所有选项后，保存配置，并选择退出以离开 menuconfig 选项。然后，从 Buildroot 文件夹输入`make`来构建您的配置和工具链。

在使用 Yocto 构建系统时，可以采取类似的步骤，确保食谱已更新并配置为仅包含所需的软件包。还有其他几个配置可以用来加固 Linux 构建环境，包括以下内容：

1.  删除未使用的语言解释器，如 Perl、Python 和 Lua。

1.  从未使用的库函数中删除死代码。

1.  删除遗留的不安全守护程序，包括但不限于 Telnet、FTP 和 TFTP。

1.  从 Busybox 中删除未使用的 shell 实用程序，如 grep、awk、wget、curl 和 sed。

1.  加固库或服务以支持加密。

1.  确保构建所选的所有软件包和库都使用最新版本。

1.  使用最新的 Linux 内核。

1.  禁用 IPv4 转发

1.  禁用 IP 源路由

1.  禁用 ICMP

1.  忽略所有广播消息

1.  禁用 IPV6

1.  启用 TCP SYN Cookie 保护

1.  使用 Linux 安全模块（包括 SELinux）。

1.  在构建后使用免费工具，如 Lynis ([`raw.githubusercontent.com/CISOfy/lynis/master/lynis`](https://raw.githubusercontent.com/CISOfy/lynis/master/lynis))，以获得加固建议。

上述列表并不是详尽无遗的。与开发人员以及相关利益相关者一起进行迭代的威胁模型练习，以确保嵌入式设备上运行的软件不会引入易受攻击的过时软件等低挂果。

# 保护第三方代码和组件

在设置工具链之后，重要的是确保软件包和第三方上游库保持更新，以防止在物联网设备投入生产后出现已知的公开漏洞。黑盒第三方软件，如 RomPager、NetUSB 和嵌入式构建工具，如 Buildroot，也应该根据漏洞数据库以及它们的变更日志进行检查，以决定何时以及是否需要更新。使用上游 BSP 驱动程序并不是一件容易的事；在发布构建之前，开发团队应该测试库和上游 BSP 驱动程序的更改，因为更新可能会导致意想不到的依赖问题。

嵌入式项目和应用程序应该维护一个包含固件镜像中包含的第三方库和开源软件的清单（BOM）。这在世界某些受监管地区和 GPL 中有时是一个要求，同时维护 BOM 也有助于改善资产和库的管理。应该检查这个清单，以确认其中没有包含任何未修补的漏洞或已知问题的第三方软件。最新的漏洞信息可以通过**国家漏洞数据库**（**NVD**）、Open Hub 或类似的第三方网站找到。

在固件发布到所有市场细分之前，确保删除所有不必要的预生产构建代码，以及死代码和未使用的应用程序代码非常重要。这包括但不限于可能由**原始设计制造商**（**ODMs**）、供应商和第三方承包商留下的用于测试或客户支持目的的后门代码和根权限帐户。通常，这是**原始设备制造商**（**OEMs**）的职责，通过使用第三章中描述的方法对二进制文件进行逆向工程，即*分析和利用固件*。为了防止 OEMs 的额外劳动力开销，ODMs 应同意**主服务协议**（**MSAs**），确保不包括后门代码或用户帐户，并且所有代码都已经过审查，以查找软件安全漏洞，并追究第三方开发公司对大规模部署到市场上的设备的责任。此外，还要考虑要求 ODMs 有信息安全人员，并建立服务级别协议（SLA）来修复关键的安全漏洞。这个食谱将向您展示如何使用免费可用的工具来保护第三方代码和组件。

# 准备工作

这个食谱需要以下工具：

+   **RetireJS**：RetireJS 可以检测使用已知漏洞的 JavaScript 库。RetireJS 可以通过其 GitHub 存储库（[`github.com/RetireJS/retire.js`](https://github.com/RetireJS/retire.js)）或通过`npm`使用以下命令进行下载：

```
npm install -g retire

```

+   **Node Security Platform**（**NSP**）：NSP 可以检测项目中使用的已知有漏洞的 NodeJS 软件包。NSP 可以通过其 GitHub 存储库（[`github.com/nodesecurity/nsp`](https://github.com/nodesecurity/nsp)）或通过`npm`使用以下命令进行安装：

```
npm install -g nsp

```

+   **LibScanner**：LibScanner 是一个免费工具，用于对 Yocto 构建环境中使用的 RPM 或 SWID 软件包列表进行解析，并与 NVD 数据库进行比对。LibScanner 可以从其 GitHub 存储库下载，网址为[`github.com/DanBeard/LibScanner`](https://github.com/DanBeard/LibScanner)。

# 如何操作...

许多物联网设备运行各种 JavaScript 代码，以帮助减轻硬件资源消耗。有时，当设备需要作为某些用例的服务器时，这些代码也会在设备上运行。有一些很好的工具可以扫描项目目录，查找项目中使用的已知有漏洞的 JavaScript 版本。首先，我们来看一下 RetireJS。

1.  要运行 RetireJS，只需运行`retire`命令，并指定 JavaScript 目录如下：

```
$ retire path/to/js/
Loading from cache: https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json
    Loading from cache: https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/npmrepository.json
    /static/js/lib/jquery-ui.js
      jquery-ui-dialog 1.8.17 has known vulnerabilities: severity: medium; bug: 6016, summary: Title cross-site scripting vulnerability; http://bugs.jqueryui.com/ticket/6016 severity: high; bug: 281, summary: XSS Vulnerability on closeText option; https://github.com/jquery/api.jqueryui.com/issues/281 https://snyk.io/vuln/npm:jquery-ui:20160721
      jquery-ui-autocomplete 1.8.17
    /static/js/lib/jquery.js
      jquery 1.7.1 has known vulnerabilities: severity: medium; bug: 11290, summary: Selector interpreted as HTML; http://bugs.jquery.com/ticket/11290 http://research.insecurelabs.org/jquery/test/ severity: medium; issue: 2432, summary: 3rd party CORS request may execute; https://github.com/jquery/jquery/issues/2432 http://blog.jquery.com/2016/01/08/jquery-2-2-and-1-12-released/

```

扫描发现项目中使用了两个有漏洞的 jQuery 库，以及相关的阅读和解释。这些发现可能会在未来打开设备的漏洞，但在生产之前发现这些问题要便宜得多。

1.  一个很好的 NodeJS 漏洞扫描工具是 NSP。与 RetireJS 一样，可以通过调用`nsp`并指定 NodeJS 项目目录或`packages.json`来执行 NSP，如下：

```
    $ nsp check /path/to/package.json 
    (+) 1 vulnerabilities found
    ┌───────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
    │               │ Command Injection                                                                                                                                                                 │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ Name          │ growl                                                                                                                                                                             │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ CVSS          │ 9.8 (Critical)                                                                                                                                                                    │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ Installed     │ 1.1.0                                                                                                                                                                             │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ Vulnerable    │ All                                                                                                                                                                               │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ Patched       │ None                                                                                                                                                                              │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ Path          │ stylus@0.22.4 > growl@1.1.0                                                                                                                                                       │
    ├───────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
    │ More Info     │ https://nodesecurity.io/advisories/146                                                                                                                                            │
    └───────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

```

NSP 发现了一个有漏洞的库，可能会导致设备受到命令注入攻击，这是物联网中常见的漏洞。

1.  如果 IoT 设备的构建系统使用 Yocto，则可以使用免费的 LibScanner 工具来查询 NVD 数据库，以查找项目安装的软件包列表中已知的易受攻击的库。要开始使用 LibScanner，请通过运行以下命令更新漏洞数据库：

```
$ ./download_xml.sh 

```

1.  更新 NVD 数据库后，可以按照以下方式运行 LibScanner 来对 Yocto 的`installed-packages.txt`文件进行扫描：

```
$ ./cli.py  --format yocto "path/to/installed-packages.txt" dbs/  > cve_results.xml 

```

1.  执行后，请查看`cve_results.xml`文件，其中包含易受攻击文件的扫描结果以及 xUnit 格式的单元测试：

```
    $ cat cve_results.xml
    <failure> Medium (6.8) - Use-after-free vulnerability in libxml2 through 2.9.4, as used in Google Chrome before 52.0.2743.82, allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors related to the XPointer range-to function. 

     CVE Published on: 2016-07-23 https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-5131 </failure>
    </testcase>
    <testcase id="CVE-2016-9318" name="CVE-2016-9318" classname="libxml2 - 2.9.4" time="0">
    <failure> Medium (6.8) - libxml2 2.9.4 and earlier, as used in XMLSec 1.2.23 and earlier and other products, does not offer a flag directly indicating that the current document may be read but other files may not be opened, which makes it easier for remote attackers to conduct XML External Entity (XXE) attacks via a crafted document. 

     CVE Published on: 2016-11-15 https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-9318 </failure>
    </testcase>
    </testsuite>

```

在设备构建之前可以使用几种工具执行静态任务，或者在设备构建后和设备运行时执行动态检查。在之前的章节中，已经讨论了动态工具，比如用于 Web 应用程序测试的 OWASP ZAP，以及可以直接在设备命令行界面上运行的 Lynis 等工具。所有这些都可以加强设备的安全性，并最大程度地减少设备遭受成功攻击的可能性。

在本章中，我们讨论了在构建和编写固件中应该纳入的几种最佳实践。建议根据您的操作系统平台（即嵌入式 Linux、RTOS、Windows IoT 等）执行自己的尽职调查，以获取与您的 IoT 设备相关的特定安全控制。


# 第九章：移动安全最佳实践

在本章中，我们将涵盖以下内容：

+   安全存储数据

+   实施身份验证控件

+   保护传输中的数据

+   安全使用 Android 和 iOS 平台组件

+   保护第三方代码和组件

+   采用反向工程保护

# 介绍

移动应用程序通常是控制消费者物联网的关键。无论是智能家居设备还是连接的车辆，移动应用程序都是攻击和保持安全的理想目标。在第五章中，*利用物联网移动应用程序*，从攻击者的角度讨论了移动应用程序的利用。本章将提供用于保护常见攻击向量的移动应用程序安全防御控件。需要注意的是，本章在移动安全最佳实践方面并不是详尽无遗的，因为关于这个主题的完整书籍都是专门写的。鼓励参考补充阅读，以更深入地了解本章描述的某些控件和最佳实践。在适当的情况下，将在整个配方中提供 Android 和 iOS 的示例。根据 OWASP 的移动安全项目([`www.owasp.org/index.php/Projects/OWASP_Mobile_Security_Project_-_Top_Ten_Mobile_Controls`](https://www.owasp.org/index.php/Projects/OWASP_Mobile_Security_Project_-_Top_Ten_Mobile_Controls))，前 10 个移动控件包括：

1.  识别和保护敏感数据。

1.  保护身份验证凭据。

1.  保护传输中的数据。

1.  正确实施用户身份验证，授权和会话管理。

1.  保持后端 API（服务）和平台（服务器）的安全。

1.  确保与第三方服务和应用程序的数据集成安全。

1.  特别关注收集和存储用户数据收集和使用的同意。

1.  实施控件以防止未经授权访问付费资源。

1.  确保移动应用程序的安全分发/配置。

1.  仔细检查任何代码的运行时解释是否存在错误。

本章将讨论与常见物联网应用程序用例相关的几个早期提到的移动安全控件。

# 安全存储数据

移动应用程序中的敏感数据取决于物联网设备的性质。许多设备可能在移动设备上存储个人数据，收集个人数据，患者健康信息（PHI），信用卡信息，并存储用于对物联网设备进行身份验证的帐户凭据。泄露的凭据或长期的会话令牌可能对智能门锁和连接的车辆产生重大影响。这些敏感数据必须通过控件和验证来进行保护。许多时候，敏感数据会无意中暴露给在移动设备上运行的第三方应用程序，用于操作系统的进程间通信（IPC）。此外，丢失移动设备，或在旅行时被盗或被扣押也并非罕见。在这些情况下，应用程序必须采用适当的安全控件来保护敏感数据，并使获取数据变得更加困难。在本章中，我们将讨论安全存储敏感数据的方法。

# 准备就绪

在这个配方中，将使用 SQLCipher 来演示安全数据库存储的方法。

SQLCipher 可以从以下网页下载：

[`www.zetetic.net/sqlcipher/`](https://www.zetetic.net/sqlcipher/)

# 如何做...

Android 和 iOS 平台都有本地方法来安全存储敏感数据。对于 Android，敏感数据可以存储在 KeyStore 中。对于 iOS，敏感数据可以存储在 Keychain 中。重要的是要注意，如果设备被 root 或越狱，Android 的 KeyStore 和 iOS 的 Keychain 内容可以被转储。但是，如果 Android 设备具有**可信执行环境**（**TEE**）或**安全元素**（**SE**），则 KeyStore 对操作系统不可直接访问，保存的数据也将无法访问。除了本地平台 API 可用于安全存储数据外，还有第三方库可用于加密磁盘上的数据或整个 SQLite 数据库，如 SQLCipher。SQLCipher 适用于 Android 和 iOS，如果 SQLite 数据库用于 IoT 设备，则应该用于安全存储数据。

1.  要在 Android 应用程序中使用 SQLCipher，我们需要创建一个活动，初始化 SQLCipher 数据库，并将数据保存在适当的数据库表和列中，如下例所示：

```
public class SQLCipherExampleActivity extends Activity { 
    @Override 
    public void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.main); 
        InitSQLCipher(); 
    } 

    private void InitSQLCipher() { 
        SQLiteDatabase.loadLibs(this); 
        File databaseFile = getDatabasePath("EncStorage.db"); 
        databaseFile.mkdirs(); 
        databaseFile.delete(); 
        SQLiteDatabase secureDatabase = SQLiteDatabase.openOrCreateDatabase(databaseFile, "PacktDB", null); 
        secureDatabase.execSQL("CREATE TABLE IF NOT EXISTS Accounts(Username VARCHAR,Password VARCHAR);"); 
        secureDatabase.execSQL("INSERT INTO Accounts VALUES('PacktUser','EncPassword');"); 
         secureDatabase.close();    
   } 
}
```

1.  在之前的示例中没有包括的一个重要步骤是建立 PRAGMA 密钥。这个 PRAGMA 密钥是 SQLCipher 数据库的加密密钥，应该在每个用户和设备的应用程序初始化期间动态生成。PRAGMA 密钥应该具有足够的熵，并且不应该硬编码到应用程序中或存储在非硬件支持的存储位置（例如，安全元素）。

Android 常见的不安全存储位置是`SharedPreferences.xml`，开发人员经常用来存储设置和配置。存储在`SharedPreferences.xml`中的数据是明文可读的，除非使用第三方包装器来加密偏好设置的值。

对于 iOS，数据不应存储在应用程序容器内的文件中，也不应存储在明文 plist 文件中。Keychain 应该用于所有凭据和令牌数据，并根据应用程序运行的上下文使用适当的 Keychain API 属性。例如，如果应用程序不在后台运行，则使用最严格的属性，如`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`，这可以防止 Keychain 项目被 iTunes 备份，或者使用`kSecAttrAccessibleWhenUnlocked`。如果应用程序需要在前台运行，则使用`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`属性。

1.  在存储数据时，有几个适用于 Android 和 iOS 的最佳实践需要遵循。常见的最佳实践包括：

1. 尽量不要存储敏感数据。

2. 只存储应用程序功能所需的数据。

3. 避免将敏感数据存储在缓存、外部存储器（SD 卡）或临时文件中。

4. 不要将敏感数据记录到磁盘或控制台。

5. 禁用对敏感输入字段的键盘缓存。

6. 限制应用程序数据的备份。

7. 如果敏感数据存储在磁盘上，加密其内容并将数据存储在防篡改的位置，如安全元素。

8. 确保应用程序在使用后和不再需要时从内存中擦除敏感数据。

9. 确保对敏感文本字段禁用剪贴板。

有时，平台安全 API（如 KeyStore 和 Keychain）可能不足以确保敏感数据的保密性和完整性。在这些情况下，建议使用应用级加密来增强保护，然后将加密数据存储在平台的安全存储位置中。

# 另请参阅

+   有关 Keychain 的更多信息，请参阅*苹果的 Keychain 服务编程指南*（[`developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html#/`](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/01introduction/introduction.html%23/)）。

+   有关 Keychain 的更多信息，请参阅*Android 的开发者*文档（[`developer.android.com/training/articles/keystore.html`](https://developer.android.com/training/articles/keystore.html)）。

+   有关使用 SQLCipher 的更多信息，请参阅*SQLCipher 的 API 开发者*文档（[`www.zetetic.net/sqlcipher/sqlcipher-api/`](https://www.zetetic.net/sqlcipher/sqlcipher-api/)）。

# 实施身份验证控制

移动应用程序的身份验证可以同时发生在服务器端和客户端。IoT 移动应用程序可以利用这两种设计模式，尽管在生产中实施时每种都有自己的风险考虑。本节将讨论一些这些风险以及服务器端和客户端身份验证的最佳实践设计实施。

# 如何做到...

安全地验证用户的一般应用程序原则也适用于移动应用程序。一个很好的参考是 OWASP 的*身份验证备忘单*（[`www.owasp.org/index.php/Authentication_Cheat_Sheet`](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)）。常见的身份验证控件和最佳实践包括：

+   适当的密码强度控制

+   密码长度

+   10 个或更多字符

+   密码复杂性策略

+   1 个大写字母，1 个小写字母，1 个数字，1 个特殊字符，并且不允许连续 2 个字符，如 222

+   强制密码历史记录

+   禁止使用过的最后三个密码（密码重用）

+   仅通过加密通信（TLS）传输凭据

+   通过`HTTP POST`主体发送凭据

+   重新验证用户以使用敏感功能

+   更改密码

+   更改帐户 PIN

+   更改安全问题

+   共享摄像头视频

+   解锁车辆

+   确保身份验证错误消息不会透露潜在的敏感信息

+   正确的错误响应如下，无效的用户名和/或密码

+   确保记录身份验证功能以检测登录失败

+   防止自动暴力攻击

+   使用 CAPTCHA 或类似功能

+   限制可疑登录尝试的速率

+   在给定阈值后暂时锁定帐户并发送电子邮件到帐户地址

+   确保多因素身份验证存在并在登录时执行，以及在使用逐步身份验证访问资源时执行。双因素方法包括：

+   除密码外，还有用户已知的值

+   通过电子邮件或短信发送的一次性密码（OTP）或代码

+   除用户密码外，还有一个 OTP 的物理令牌

前述项目适用于 Web 应用程序、混合移动应用程序，甚至本机移动应用程序。以下项目是特定于移动设备的身份验证最佳实践，可实施到应用程序中：

+   如果使用生物识别技术，请确保使用 KeyStore 和 Keychain 而不是基于事件的方法

+   会话在服务器端被使无效

+   应用程序列出最后的登录活动并允许用户阻止设备

+   避免使用设备 UUID、IP 地址、MAC 地址和 IMEI 进行身份验证或授权目的

+   在移动应用程序之外使用第三方 OTP 应用程序（例如 Google 或 Salesforce 认证器）

Android 特定的身份验证实践如下所示：

+   使用 Android 的 FingerprintManager 类（[`developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.html`](https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager.html)），使用`KeyGenerator`类与非对称密钥对。有关使用非对称密钥对的示例，请参见[`github.com/googlesamples/android-AsymmetricFingerprintDialog`](https://github.com/googlesamples/android-AsymmetricFingerprintDialog)。

+   在 Android Nougat API 24 中引入，使用`setInvalidatedByBiometricEnrollment`（`boolean invalidateKey`）方法来使新的指纹无法从移动设备上检索密钥。

+   应用程序应利用 SafetyNet reCAPTCHA API 来保护免受基于机器人的暴力攻击的身份验证。

要使用 SafteyNet reCAPTCHA API，必须执行以下步骤：

1.  通过[`www.google.com/recaptcha/admin#androidsignup`](https://www.google.com/recaptcha/admin%23androidsignup)注册 reCAPCTHA 密钥对：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/018e9535-f65e-46ef-946c-7ecc3e5aa292.png)

1.  如果尚未配置，必须添加 SafetyNet API 依赖项和 Google Play 服务。例如，在项目构建 gradle 文件中包括`com.google.android.gms:play-services-safetynet:11.4.2`，如下所示：

```
apply plugin: 'com.android.application' 

android { 
    compileSdkVersion 23 
    buildToolsVersion '25.0.0' 

    defaultConfig { 
        applicationId "jakhar.aseem.diva" 
        minSdkVersion 15 
        targetSdkVersion 23 
        versionCode 1 
        versionName "1.0" 
    } 
    buildTypes { 
        release { 
            minifyEnabled enabled 
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro' 
        } 
    } 
    sourceSets { 
        main { 
            jni.srcDirs = [] 
        } 
    } 
} 

dependencies { 
    compile fileTree(dir: 'libs', include: ['*.jar']) 
    testCompile 'junit:junit:4.12' 
    compile 'com.android.support:appcompat-v7:23.1.0' 
    compile 'com.android.support:design:23.1.0' 
    compile 'com.google.android.gms:play-services-safetynet:11.4.2' 
}
```

1.  必须通过`verifyWithRecaptcha()`（[`developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNetClient#verifyWithRecaptcha(java.lang.String)`](https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNetClient#verifyWithRecaptcha(java.lang.String))）发出调用验证请求的请求。此请求必须包含 API 站点密钥作为参数，并且必须覆盖`onSuccess()`和`onFailure()`方法。以下代码片段显示了如何调用此方法，提供了 Android 的开发人员指南（[`developer.android.com/training/safetynet/recaptcha.html#send-request`](https://developer.android.com/training/safetynet/recaptcha.html%23send-request)）：

```
public void onClick(View v) { 
    SafetyNet.getClient(this).verifyWithRecaptcha(YOUR_API_SITE_KEY) 
        .addOnSuccessListener((Executor) this, 
            new OnSuccessListener<SafetyNetApi.RecaptchaTokenResponse>() { 
                @Override 
                public void onSuccess(SafetyNetApi.RecaptchaTokenResponse response) { 
                    // Indicates communication with reCAPTCHA service was 
                    // successful. 
                    String userResponseToken = response.getTokenResult(); 
                    if (!userResponseToken.isEmpty()) { 
                        // Validate the user response token using the 
                        // reCAPTCHA siteverify API. 
                    } 
                } 
        }) 
        .addOnFailureListener((Executor) this, new OnFailureListener() { 
                @Override 
                public void onFailure(@NonNull Exception e) { 
                    if (e instanceof ApiException) { 
                        // An error occurred when communicating with the 
                        // reCAPTCHA service. Refer to the status code to 
                        // handle the error appropriately. 
                        ApiException apiException = (ApiException) e; 
                        int statusCode = apiException.getStatusCode(); 
                        Log.d(TAG, "Error: " + CommonStatusCodes 
                                .getStatusCodeString(statusCode)); 
                    } else { 
                        // A different, unknown type of error occurred. 
                        Log.d(TAG, "Error: " + e.getMessage()); 
                    } 
                } 
        }); 
} 
```

1.  通过`SafetyNetApi.RecaptchaTokenResult.getTokenResult()`验证响应令牌。JSON HTTP 响应的示例如下：

```
{ 
  "success": true|false, 
  "challenge_ts": timestamp,  // timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ) 
  "apk_package_name": string, // the package name of the app where the reCAPTCHA was solved 
  "error-codes": [...]        // optional 
} 
```

1.  接下来，必须添加逻辑来处理失败和错误。SafetyNet reCAPTCHA API 使用七个状态代码：

1\. `RECAPTCHA_INVALID_SITEKEY`

2\. `RECAPTCHA_INVALID_KEYTYPE`

3\. `RECAPTCHA_INVALID_PACKAGE_NAME`

4\. `UNSUPPORTED_SDK_VERSION`

5\. `TIMEOUT`

6\. `NETWORK_ERROR`

7\. `ERROR`

有关每个状态代码的详细信息，请参阅以下参考页面：

[`developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNetStatusCodes.`](https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNetStatusCodes)

接下来列出了特定于 iOS 的身份验证实践：

+   将应用程序的秘密存储在受访问控制的钥匙串列表中以供特定应用程序使用。可以在苹果的开发人员文档中找到使用钥匙串和 Touch ID 的示例代码片段，网址为[`developer.apple.com/library/content/samplecode/KeychainTouchID/Listings/KeychainTouchID_AAPLKeychainTestsViewController_m.html`](https://developer.apple.com/library/content/samplecode/KeychainTouchID/Listings/KeychainTouchID_AAPLKeychainTestsViewController_m.html)。

+   确保应用程序从`LAContext.evaluatedPolicyDomainState`中读取，以检查`evaluatedPolicyDomainState`值是否已更改，指示已注册的 Touch ID 指纹是否已更改。

+   除非应用程序需要，否则禁止钥匙串通过`kSecAttrSynchronizable`与 iCloud 同步。

Touch ID 是一种常见的用户身份验证方法；但是，有几种方法和工具可以绕过仅使用本地身份验证框架的应用程序。如前所述，使用钥匙串 ACL 可以防止攻击者在运行时覆盖`LAContextevaluatePolicy:localizedReason:reply`方法或对应用程序本身进行打补丁。

# 另请参阅

+   有关 iOS 钥匙串服务的更多信息，请参阅*钥匙串服务编程指南*（[`developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html`](https://developer.apple.com/library/content/documentation/Security/Conceptual/keychainServConcepts/02concepts/concepts.html)）

+   有关使用指纹 API 对远程服务器进行身份验证的更多信息，请访问 Android 的开发者博客（[`android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html`](https://android-developers.googleblog.com/2015/10/new-in-android-samples-authenticating.html)）

+   查看安卓开发者页面上关于 SafetyNet reCAPTCHA API 的信息（[`developer.android.com/training/safetynet/recaptcha.html`](https://developer.android.com/training/safetynet/recaptcha.html)）

# 保护数据在传输中

保护物联网移动应用的端到端通信一直是一个难题。通常，数据会通过明文协议泄露，比如 HTTP 或 UDP（SIP）用于音频传输到移动应用。偶尔，物联网制造商被发现向第三方泄露数据，这些第三方只通过 HTTP 通信或者使用较不安全的加密配置进行内容识别或崩溃报告分析服务。保护数据在传输中的目标是确保移动应用、物联网设备和 API 端点之间交换的数据的机密性和完整性。移动应用必须使用 TLS 建立安全加密通道进行网络通信，并配置适当的密码套件。对于智能锁或连接车辆等设备，这是必须的。本文将介绍保护物联网移动应用中传输数据的最佳实践。

# 如何做...

保护移动应用中传输数据有共同的要求和最佳实践。保护传输数据的最佳实践包括但不限于以下内容：

+   使用平台支持的最新 TLS 和密码套件配置

+   验证服务器 X.509 证书

+   验证证书主机名

+   只接受由受信任的证书颁发机构签名的证书，其中包括公共 CA 以及内部受信任的 CA

+   禁止使用自签名证书

+   将连接固定到受信任的证书和/或公钥

实现在安卓和 iOS 之间有所不同。两个平台都有本地的加密 API；但是，也有第三方封装库可用，但可能没有证书固定等功能。

# 安卓

在上面的示例中，一个安卓应用程序创建了一个包含 CA（受信任证书）的 KeyStore，初始化了 TrustManager，其工作是仅验证 KeyStore 中的证书：

1.  创建线程安全的`KeyPinStore`类（public static synchronized）：

```
public class KeyPinStore { 

    private static KeyPinStore instance = null; 
    private SSLContext sslContext = SSLContext.getInstance("TLS"); 

    public static synchronized KeyPinStore getInstance() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException{ 
        if (instance == null){ 
            instance = new KeyPinStore(); 
        } 
        return instance; 
    } 
```

1.  加载应用程序资产目录中的 CA：

```
private KeyPinStore() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException{ 
        CertificateFactory cf = CertificateFactory.getInstance("X.509"); 
        // randomCA.crt should be in the Assets directory 
        InputStream caInput = new BufferedInputStream(MainActivity.context.getAssets().open("TrustedCompanyCA.crt")); 
        Certificate ca; 
        try { 
            ca = cf.generateCertificate(caInput); 
            System.out.println("ca=" + ((X509Certificate) ca).getSubjectDN()); 
        } finally { 
            caInput.close(); 
        }
```

1.  创建包含我们指定的受信任 CA 的 KeyStore：

```
String keyStoreType = KeyStore.getDefaultType(); 
KeyStore keyStore = KeyStore.getInstance(keyStoreType); 
keyStore.load(null, null); 
keyStore.setCertificateEntry("ca", ca); 
```

1.  创建 TrustManager 以验证我们 KeyStore 中的 CA：

```
String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm(); 
TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm); 
tmf.init(keyStore); 
```

1.  创建使用我们的 TrustManager 的 SSLContent：

```
sslContext.init(null, tmf.getTrustManagers(), null); 
    } 

    public SSLContext getContext(){ 
        return sslContext; 
    } 
} 
```

1.  告诉 URLConnection 在与应用程序的 API 端点通信时使用来自我们的 SSLContext 的 SocketFactory：

```
URL url = new URL("https://example.com/rest/apiEndpoint"); 
HttpsURLConnection urlConnection = 
    (HttpsURLConnection)url.openConnection(); 
urlConnection.setSSLSocketFactory(context.getSocketFactory()); 
InputStream in = urlConnection.getInputStream(); 
copyInputStreamToOutputStream(in, System.out); 
```

一个可以帮助确保正确的 TLS/SSL 配置的工具是 Google 发布的 nogotofail。nogotofail 不仅检查配置，还确保不使用易受攻击的 TLS/SSL 协议，以及通过 MITM 技术查看从客户端设备发送的数据。要了解有关 nogotofail 的更多信息，请访问项目的 GitHub 页面[`github.com/google/nogotofail`](https://github.com/google/nogotofail)。

# iOS

类似的操作可以用于在 iOS 中将证书和/或证书的公钥指纹固定。固定是通过`NSURLConnectionDelegate`执行的，其中必须在`connection:didReceiveAuthenticationChallenge:`中实现`connection:canAuthenticateAgainstProtectionSpace:`和`connection:didReceiveAuthenticationChallenge:`，并调用`SecTrustEvaluate`执行 X509 验证检查。在部署此类检查时，可以使用 OWASP 提供的 iOS 固定应用程序示例作为参考。可以通过以下链接下载示例程序：

[`www.owasp.org/images/9/9a/Pubkey-pin-ios.zip`](https://www.owasp.org/images/9/9a/Pubkey-pin-ios.zip)

除了所有应用程序在使用 TLS 时应遵循的一般最佳实践外，iOS 还有一个新功能，开发人员可以利用，并且在将来提交到苹果的 App Store 时将被要求（[`developer.apple.com/news/?id=12212016b`](https://developer.apple.com/news/?id=12212016b)）。这个功能被称为**应用传输安全**（**ATS**），在 iOS 9 中引入，并默认启用。ATS 要求应用程序使用 TLSv1.2 进行 HTTPS 通信，使用**完美前向保密**（**PFS**）以及特定的密码套件。如果应用程序不符合最低要求，将不允许连接到 iOS 应用程序。这对所有物联网设备都是很好的；然而，有方法可以绕过 ATS。具体来说，开发人员可以通过在`Info.plist`文件中使用`NSAllowsArbitraryLoads`配置来完全禁用 ATS，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/923236c5-0e58-41f1-89e5-0814cdd7ef0c.png)

不幸的是，由于缺乏加密和/或 PKI 知识，这在物联网应用程序中非常普遍。ATS 还可以提供针对每个域或全局的异常，而不是完全禁用 ATS。以下是可以应用于以下配置的非详尽列表的异常：

+   禁用 PFS（`NSExceptionRequiresForwardSecrecy`）

+   为媒体禁用 ATS（`NSAllowsArbitraryLoadsForMedia`）

+   允许通过 HTTP 进行不安全连接（`NSExceptionAllowsInsecureHTTPLoads`）

+   降低最低 TLS 版本（`NSExceptionMinimumTLSVersion`）

+   允许连接到本地域名（`NSAllowsLocalNetworking`）

苹果提供了一个检查应用传输安全问题的工具，名为 nscurl。可以通过执行以下命令来使用 nscurl：

```
$ nscurl --ats-diagnostics https://www.packtpub.com  
```

苹果正在做出有希望的改变，以影响开发人员确保数据在传输中得到安全保护。如前所述，所有提交到 App Store 的应用程序将被要求在未来支持 ATS，具体时间由苹果宣布。

# 另请参阅

+   OWASP 提供的一个示例 Android 公钥固定应用程序可以通过以下 URL 下载：

[`www.owasp.org/images/1/1f/Pubkey-pin-android.zip`](https://www.owasp.org/images/1/1f/Pubkey-pin-android.zip)

+   请参阅以下苹果开发人员指南，了解有关 ATS 要求的更多信息：

[`developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html#//apple_ref/doc/uid/TP40009251-SW57`](https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html%23/apple_ref/doc/uid/TP40009251-SW57)

# 安全地使用 Android 和 iOS 平台组件

当物联网移动应用程序执行或检索来自第三方应用程序的命令时，内部平台 API 用于**进程间通信**（**IPC**）。IPC 可用于集成应用程序，使其调用费用跟踪应用程序、IFTTT 等第三方服务应用程序，或亚马逊的 Alexa 等个人助手。Android 等平台提供了丰富的 IPC 功能，而 iOS 只提供了几个选项。大多数物联网应用程序使用平台和硬件功能与物理世界进行交互，这反过来会在对手成功利用漏洞时产生更大的影响。在本教程中，我们将讨论如何在 IPC 周围应用安全控制以及如何安全地使用平台 API。

# 如何做到…

与源自应用程序的命令在移动平台上进行交互是一种强大的能力。如果没有得到适当的保护，未经授权的应用程序可能会劫持命令并访问本不应被未经意的第三方接收的数据。在使用平台 API 时，应考虑以下做法：

+   除非这些机制得到适当保护，否则不要通过 IPC 导出敏感功能。

+   来自外部来源和用户的输入应该在必要时进行验证和清理。这包括通过用户界面、IPC 机制（如意图、自定义 URL 处理程序）和网络来源接收的数据。

+   WebViews 应该配置为仅允许加载所需的最小协议处理程序，如 HTTPS，并禁用其他危险的处理程序，如`file://`、`tel://`、`sms://`和`app-id://`。

+   将 IPC 调用限制为受信任应用程序的白名单。

+   将 Web 页面和 URL 处理程序列入白名单，以便本地或远程加载。

+   仅请求应用程序功能所需的最小权限集。

+   通过 WebViews 公开的本地方法应该验证，只有应用程序沙盒内的 JavaScript 才能被渲染。

+   除非明确需要，否则 WebViews 应该禁用 JavaScript。

+   序列化应该只使用安全的序列化 API，并进行加密签名。

大多数列出的做法都可以应用于 Android 和 iOS 平台；但是，根据应用程序的功能，应该审查特定的考虑因素，如 Android 权限、自定义权限和保护级别。

以下是一个名为`IOT_COOKBOOK_ACTIVITY`的自定义权限的示例，当启动`MAIN_ACTIVITY``Activity`时需要该权限。

1.  第一个代码块使用标签定义了新的权限，并描述了`Activity`。接下来，根据权限类型设置了保护级别。一旦权限被定义，就可以通过在应用程序的`AndroidManifest.xml`文件中指定`uses-permission`来强制执行该组件上的权限。在下面的示例中，第二个块是我们将使用我们定义的权限来限制的组件。可以通过添加`android:permission`属性来强制执行：

```
<permission android:name="com.packtpub.cookbook.permission.IOT_COOKBOOK_ACTIVITY" 
        android:label="Start main Activity in packtpub" 
        android:description="Allow only apps signed with the same certificate to launch this Activity." 
        android:protectionLevel="signature" /> 

<activity android:name="MAIN_ACTIVITY" 
    android:permission="com.packtpub.cookbook.permission.IOT_COOKBOOK_ACTIVITY"> 
    <intent-filter> 
        <action android:name="android.intent.action.MAIN" /> 
        <category android:name="android.intent.category.LAUNCHER"/> 
     </intent-filter> 
</activity> 
```

1.  现在创建了新的权限`IOT_COOKBOOK_ACTIVTY`，应用程序可以在`AndroidManifest.xml`文件中使用`uses-permission`标签请求该权限。在这种情况下，必须是使用相同证书签名的应用程序才能启动`MAIN_ACTIVITY`：

```
<uses-permission android:name="com.example.myapp.permission.IOT_COOKBOOK_ACTIVITY"/> 
```

在引入自定义权限和保护级别时，始终参考 Android 的开发者文档是一个好主意。所有 Android 权限都可以在 Android 开发者文档中找到：[`developer.android.com/guide/topics/permissions/requesting.html`](https://developer.android.com/guide/topics/permissions/requesting.html)。

在 iOS 应用程序中，由于 iOS 的封闭生态系统，权限不适用。但是，iOS 和 Android 共享 WebViews，这使得可以在应用程序内加载网页。与 Web 应用程序类似，恶意代码可以在 WebViews 中执行。在减少 IoT 应用程序的攻击面时，这一点很重要。

1.  以下代码片段说明了如何在 iOS 应用程序中禁用 WKWebViews 中的 JavaScript：

```
#import "ViewController.h" 
#import <WebKit/WebKit.h> 
@interface ViewController ()<WKNavigationDelegate,WKUIDelegate> 
@property(strong,nonatomic) WKWebView *webView; 
@end 

@implementation ViewController 

- (void)viewDidLoad { 

    NSURL *url = [NSURL URLWithString:@"https://www.packtpub.com/"]; 
    NSURLRequest *request = [NSURLRequest requestWithURL:url]; 
    WKPreferences *pref = [[WKPreferences alloc] init]; 

    [pref setJavaScriptEnabled:NO]; 
    [pref setJavaScriptCanOpenWindowsAutomatically:NO]; 

    WKWebViewConfiguration *conf = [[WKWebViewConfiguration alloc] init]; 
    [conf setPreferences:pref]; 
    _webView = [[WKWebView alloc]initWithFrame:CGRectMake(self.view.frame.origin.x,85, self.view.frame.size.width, self.view.frame.size.height-85) configuration:conf] ; 
    [_webView loadRequest:request]; 
    [self.view addSubview:_webView]; 

}
```

1.  对于 Android 应用程序，禁用 JavaScript 是通过配置 WebView 的`WebSettings`来完成的，如下所示。还应该配置其他设置，如禁用文件系统访问、关闭插件和关闭地理位置信息（如果不需要）：

```
WebView webview = new WebView(this); 
WebSettings webSettings = webview.getSettings(); 
webSettings.setJavaScriptEnabled(false); 
webView.getSettings().setPluginState(WebSettings.PluginState.OFF); 
webView.getSettings().setAllowFileAccess(false); 
webView.getSettings().setGeolocationEnabled(false); 
setContentView(webview); 
webview.loadUrl("https://www.packetpub.com/"); 
```

在考虑最小权限和深度安全原则的情况下，应用程序应该只利用和暴露平台组件以满足所需的业务功能。作为一个经验法则，从第三方应用程序发送和检索的任何数据都应该被视为不可信，并进行适当的验证。

# 保护第三方代码和组件

与所有软件一样，移动应用程序大量使用第三方库和包装器来执行诸如发出 HTTP 请求或加密对象之类的功能。这些库也可能会给应用程序引入弱点，暴露机密信息或影响应用程序本身的完整性。因此，应该审查第三方代码以发现漏洞，并在适用的情况下进行更新和测试。对于依赖第三方混合框架和库来发送、接收和保存数据的混合应用程序来说，这一点尤为重要。本文将讨论确保第三方代码不会给物联网应用程序引入漏洞的方法。

# 操作方法...

在第八章中，*固件安全最佳实践*，讨论了使用 NSP 和 Retire.js 扫描 JavaScript 库的方法，这些方法仍然适用于移动应用程序。为确保第三方代码不会给移动应用程序引入安全漏洞，应考虑以下建议：

+   使用工具如 nsp、Retirejs 和 dependency-check ([`github.com/jeremylong/DependencyCheck`](https://github.com/jeremylong/DependencyCheck)) 连续记录库和框架的版本及其依赖关系

+   为移动应用程序中使用的所有组件和第三方软件创建清单

+   通过分析工具连续监视 NVD 等漏洞数据库，以自动化流程

+   分析第三方库以确保它们在运行时被调用，并删除应用功能不需要的函数

+   确保混合框架使用最新版本。

+   监视混合框架的发布和博客，以确保没有已知的带有漏洞的组件在使用中

+   在框架开发者没有合并上游库的情况下，修补易受攻击的库

+   监视使用的开源代码库以发现安全问题和关注点

+   确保混合框架插件在使用前已经审查过安全漏洞

+   利用更新的安卓版本 API 来利用新引入的功能（苹果强制 iOS 更新）

+   审查安卓和 iOS 的安全公告以发现平台漏洞和新的安全功能

最常见的移动混合框架之一是 Apache 的 Cordova。Cordova 可以通过以下命令更新到 iOS 和安卓：

```
cordova platform update ios
cordova platform update android@<version number>

```

Cordova 以受到研究人员的关注而闻名，并且通常在新版本中包含了针对安卓和 iOS 的安全更新。Cordova 的发布说明可以在他们的博客中找到，位于 [`cordova.apache.org/blog/`](https://cordova.apache.org/blog/)。一个寻找尚未发布的错误的好地方是框架的错误跟踪系统，比如 Cordova 的 ([`issues.apache.org/jira/projects/CB/summary`](https://issues.apache.org/jira/projects/CB/summary))。你会惊讶地看到修复、报告和关闭的错误数量。例如，另一个常用的混合框架是 Xamarin。Xamarin 的凭证管理器在 2014 年 4 月至 2016 年底之间使用了一个硬编码的安卓密钥库密码，使得账户凭证面临被妥协的风险，直到后来修复了这个问题。这可以在项目的 GitHub 仓库中找到 [`github.com/xamarin/Xamarin.Auth/issues/55`](https://github.com/xamarin/Xamarin.Auth/issues/55)。

# 另请参阅

+   谷歌对在 Google Play 中使用的设备进行快照，并将这些数据发布到仪表板上，以帮助支持不同设备的优先级排序 ([`developer.android.com/about/dashboards/index.html`](https://developer.android.com/about/dashboards/index.html))

+   每个月，谷歌都会发布 Android 安全公告，列出公告、CVE 漏洞、严重程度和缓解措施。Android 安全公告可以在[`source.android.com/security/bulletin/`](https://source.android.com/security/bulletin/)找到。

+   苹果每年都会发布一份 iOS 安全指南，详细介绍平台安全功能和新的 iOS 版本的安全控制能力。iOS 安全指南可以在[`www.apple.com/business/docs/iOS_Security_Guide.pdf`](https://www.apple.com/business/docs/iOS_Security_Guide.pdf)找到。

# 采用反向工程保护

当存在内部和外包团队的代码库用于用户体验（UX）、特定功能集（例如在应用启动期间查找设备、确保规则设置正确执行等）时，编写安全代码可能会很困难，还有其他一些功能，例如确保应用更新不会对网络中的物联网设备产生负面影响。对于一个应用来说，存在这样的复杂性，错误很可能会被发现，并且安全控制可能会被攻击者绕过。是的，这对于任何软件来说都是不可避免的，尽管有技术可用于使反向工程对攻击者更加困难，以便攻击者不会妥协应用程序并窃取公司的知识产权（IP）。

这些技术可以内置到应用程序逻辑中，以防止运行时修改，通过对应用程序类进行混淆来进行应用程序二进制文件的静态分析，并对数据进行分段以准备潜在的妥协。重要的是要注意，应用程序仍然需要在应用程序中构建安全控制，而不是用第三方软件保护替换控制。本文将介绍使应用程序更具抵抗力的做法。这些做法不仅会使应用程序更具抵抗力，还将作为应用程序反滥用系统的一部分，为应用程序提供深度防御。

# 如何做…

在实施应用程序反向工程控制和代码修改技术时，应遵循以下做法：

+   应用程序应该检测并响应已越狱或越狱设备，可以通过警告用户或终止应用程序来实现

+   通过混淆类和方法来阻碍动态分析对构建的影响

+   在可能的情况下，首选硬件支持的进程隔离，而不是混淆

+   应用程序应该防止调试并阻止调试器的连接

+   应用程序应该检测反向工程工具和框架的存在

+   应用程序应该检测是否在模拟环境中运行，并做出适当的响应

+   生产版本应该剥离符号

+   生产版本不应包含调试代码或可调试功能，例如`android:debuggable="false"`

+   Android 应用程序可以使用 SafetyNet Attestation API 兼容性检查来确保应用程序未被未知来源修改

+   应该使用 SafetyNet Verify Apps API 来检查设备上是否安装了任何潜在有害的应用程序（[`developer.android.com/training/safetynet/verify-apps.html`](https://developer.android.com/training/safetynet/verify-apps.html)）

iOS 应用程序可以寻找常见的越狱基于文件的检查，例如以下列表（[`github.com/OWASP/owasp-mstg/blob/master/Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06j-Testing-Resiliency-Against-Reverse-Engineering.md)）：

```
/Applications/Cydia.app
/Applications/FakeCarrier.app
/Applications/Icy.app
/Applications/IntelliScreen.app
/Applications/MxTube.app
/Applications/RockApp.app
/Applications/SBSettings.app
/Applications/WinterBoard.app
/Applications/blackra1n.app
/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist
/Library/MobileSubstrate/DynamicLibraries/Veency.plist
/Library/MobileSubstrate/MobileSubstrate.dylib
/System/Library/LaunchDaemons/com.ikey.bbot.plist
/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist
/bin/bash
/bin/sh
/etc/apt
/etc/ssh/sshd_config
/private/var/lib/apt
/private/var/lib/cydia
/private/var/mobile/Library/SBSettings/Themes
/private/var/stash
/private/var/tmp/cydia.log
/usr/bin/sshd
/usr/libexec/sftp-server
/usr/libexec/ssh-keysign
/usr/sbin/sshd
/var/cache/apt
/var/lib/apt
/var/lib/cydia  
```

此外，iOS 应用程序可以尝试执行根级系统 API 调用或通过向应用程序沙盒之外的文件写入数据来检测设备是否已越狱。

安卓应用程序可以使用类似的方法来检查常见的已 root 设备文件，并尝试以 root 身份执行命令。常见的已 root 文件和应用程序列表如下所示（[`github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md`](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md)）：

```
    /system/xbin/busybox
    /sbin/su
    /system/bin/su
    /system/xbin/su
    /data/local/su
    /data/local/xbin/su
    com.thirdparty.superuser
    eu.chainfire.supersu
    com.noshufou.android.su
    com.koushikdutta.superuser
    com.zachspong.temprootremovejb
    com.ramdroid.appquarantine

```

此外，检查自定义的 Android ROM 版本可以指示已 root 设备，尽管这不是一个确定的方法。

应该使用多种检查和防御方法来确保弹性。总体目标是确保攻击者无法篡改、修改代码、执行运行时修改和逆向工程应用程序包以防止滥用。前述实践中的一些可以在应用程序启动时和整个运行时引入到应用程序逻辑中。商业解决方案可用于执行一些早期列出的实践以及更多内容；但是，在集成到应用程序之前，应该经过审查。

# 还有更多...

要了解移动应用程序逆向工程和未经授权的代码修改的风险，请参考 OWASP 的逆向工程和代码修改预防项目[`www.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project`](https://www.owasp.org/index.php/OWASP_Reverse_Engineering_and_Code_Modification_Prevention_Project)。该项目非常好地描述了技术和业务风险用例，并提供了补充的缓解建议。

# 另请参阅

+   有关通过 SafetyNet API 请求兼容性检查的更多信息，请参阅以下 Android 开发者页面（[`developer.android.com/training/safetynet/attestation.html#cts-check`](https://developer.android.com/training/safetynet/attestation.html#cts-check)）。


# 第十章：安全硬件

在本章中，我们将涵盖以下内容：

+   硬件最佳实践

+   不常见的螺丝类型

+   防篡改和硬件保护机制

+   侧信道攻击保护

+   暴露的接口

+   加密通信数据和 TPM

# 介绍

如今市场上大多数的物联网设备在硬件安全方面存在失败，即无法保护硬件免受攻击者的访问。无论是 IP 摄像头、婴儿监视器、医疗设备、企业物联网、智能可穿戴设备还是智能电视，一旦开始关注其安全性，就很有可能会有一名技术水平适中的攻击者能够打开设备（由于没有/很少有防止打开设备的保护措施），读取各种芯片，识别其数据表（由于缺少隐藏芯片身份的保护措施），访问芯片中的数据（当没有防止访问芯片的保护措施时），通过各种接口与设备进行交互（因为没有防止暴露接口的保护措施），等等。

在本章中，我们将介绍设备开发人员和制造商可以采取的各种步骤，以保护物联网设备中使用的嵌入式设备硬件。尽管使设备 100%安全几乎是不可能的，但本章提到的步骤将有助于确保你所工作的设备遵循了一个非常良好的安全姿态，这对攻击者来说是很难突破的。

# 硬件最佳实践

但在深入讨论可以用来保护硬件的各种细节之前，让我们简要讨论一下保护嵌入式设备所需采取的方法。

在构建嵌入式设备时需要考虑的一点是，一旦产品上市，大多数基于硬件的漏洞就无法修复。这意味着在与硬件打交道时，你需要从一开始就非常小心。

在为物联网解决方案构建硬件设备时需要注意的另一点是，始终要考虑如果攻击者能够接触硬件，他将获得哪些资源。这意味着如果攻击者能够打开物联网设备，他将在 PCB 上看到哪些可见的组件。此外，如果攻击者进一步并通过 shell 访问硬件接口，他能做些什么。

在构建嵌入式设备时应考虑这些事项。

以下是在嵌入式设备的硬件设计和开发过程中应遵循的一些最佳实践：

+   确保你的设备具有防篡改和硬件保护机制

+   通过使用独特的螺丝或使用其他方法将硬件的各个部分组合在一起，可以改善逆向工程的复杂性

+   确保攻击者无法接触/获取 UART 和 JTAG 等常见的硬件访问方式

+   利用**可信平台模块**（**TPM**）保护，以进一步加强设备安全性

# 不常见的螺丝类型

硬件攻击者的第一步是打开设备，查看 PCB 上的芯片和各种暴露的接口。可以通过使用不常见的螺丝或使用超声波焊接或高温胶封闭多个硬件外壳来一定程度上保护这一点。

以下图显示了一些常见的螺丝类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/58046357-fd8f-4376-aa88-81a65ee5ba16.png)

来源：http://thecraftsmanblog.com/wp-content/uploads/2013/09/Screw-Drive-Types.png

如果你决定使用独特/不常见的设备螺丝，将使攻击者更难打开你的设备，在大多数情况下唯一的选择将是强行打开。通过添加组件来抵抗开启设备的行为，甚至普通的打开行为，这将在下一节中讨论。

# 防篡改和硬件保护机制

防篡改意味着使用专门的组件来防止对给定设备的篡改。实施防篡改的一种常见且有效的方式是在设备中添加防篡改检测开关、传感器或电路，可以检测某些动作，如打开设备或强行破坏设备，并根据此采取行动，如删除闪存或使设备无法使用。

除此之外，强烈建议通过去除它们的标签、用环氧树脂隐藏它们，甚至将芯片封装在安全的外壳中来保护敏感芯片和组件。

实施防篡改的其他技术包括整合紧密的气流通道、安全螺丝和硬化钢外壳，所有这些都会使对设备的篡改变得极其困难。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b344f9ba-5298-40c7-bb84-741ba876e442.png)

电源插座中的安全螺丝

大多数设备制造商还实施了一些无效的防篡改保护措施。以下是 TP-Link MR3020 的图片，它使用胶水来保护和隐藏 UART 端口，但显然没有成功：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d49498ab-e7da-4bc9-a4d8-edea1257b40b.png)

在这种情况下，可以使用纸刀非常容易地去除胶水，然后暴露出底层的 UART 接口。

# 侧信道攻击保护

保护硬件的明显机制之一是实施和启用加密。然而，存在攻击可以绕过加密，或者密钥可以非常容易地获得。

侧信道攻击是一种高级的硬件利用技术，攻击者利用不同的信息源，如功耗变化、时序分析、电磁数据变化和声音信息，提取更多信息，这些信息可以用来破坏目标设备。

**直接内存攻击**（**DMA**）是一种侧信道攻击类型，让攻击者可以直接访问与某项活动功能相关的组件，而不是按照通常的路径。例如，如果我们以 USB 为例，USB 连接到控制器集线器/**平台控制器集线器**（**PCH**），可以通过**直接内存访问**（**DMA**）访问。

这些攻击很难防范，然而，以下是一些可以采取的措施来防范这些类型的攻击：

+   在设备中使用组件，减少系统外传的整体信息，无论是电磁辐射还是声音。

+   在执行敏感活动时增加额外的噪音，使攻击者更难提取信息。

+   确保攻击者无法获得对不需要的组件的任何物理访问。

# 暴露的接口

在物联网设备中保护硬件最重要的事情之一是在设备上市时禁用和移除 UART 和 JTAG 接口，以及硬件中的任何其他诊断功能。

另一个重要的考虑因素是，即使没有可见的外部接口，攻击者也可以直接连接到芯片的引脚，以获取对 UART、JTAG 等的访问权限。这是通过阅读芯片组的数据表，找出哪些引脚用于什么功能，然后进行必要的连接来实现的。在这里可以采取的一项措施是增加一些复杂性，将接口深深地放置在不同层之间，通过*过孔*而不是暴露在一个可见层上。然而，只有在设备开发者在以后的某个时间点需要暴露的接口时才应该这样做。在所有其他实际情况下，这些接口应该被移除。另一个值得注意的安全保护是添加硬件和软件保险丝，可以防止芯片被读取或写入。

这里需要注意的一点是，基本的保护机制，如切断轨道，效率极低，并且可以被一名技能适中的攻击者绕过。

然而，通过使用焊接桥，切断的轨道可以重新连接以重新启用 JTAG，并利用其他技术进一步利用它。

# 加密通信数据和 TPM

尽管加密将成为固件安全的一部分，攻击者通常可以嗅探两个不同硬件组件之间传递的数据。为了确保您的敏感信息不会落入攻击者手中，请确保您加密了传输中以及静止状态下的数据。

在谈论嵌入式设备中的加密时，另一个重要考虑因素是执行某种加密功能所需的资源量。

由于设备资源有限，执行极强的加密可能不可行-因此，在硬件中应该提前考虑并实施加密和可用性之间的良好平衡。

如果可能，并且芯片支持，利用 TPM 存储各种加密密钥，这也可以提供诸如信任根之类的功能，防止对启动过程的修改。大多数 TPM 支持有效的硬件随机数生成器和在 200 毫秒内计算 2048 位 RSA 签名的能力。

如果基于 TPM 的安全不可行，另一种选择是使用复制保护加密狗或硬件安全模块（HSM），在那里存储加密密钥。这也可以在设备运行时使用，以防止固件修改和后门攻击，从而增强设备安全性。


# 第十一章：高级物联网利用和安全自动化

在本章中，我们将涵盖以下内容：

+   查找 ROP 小工具

+   链接 Web 安全漏洞

+   为固件配置持续集成测试

+   为 Web 应用程序配置持续集成测试

+   为移动应用程序配置持续集成测试

# 介绍

为了利用物联网的漏洞并能够保护自己免受攻击，需要自动化来开发武器化的概念证明，并为防御安全团队提供可扩展性。如果安全团队无法跟上代码推送和开发的速度，就会引入漏洞。此外，安全团队需要适应开发团队的速度，不要阻碍他们当前的安全测试和审查流程。本章将介绍高级物联网利用技术，以及以自动化方式发现和防止物联网漏洞的方法。

# 查找 ROP 小工具

在利用嵌入式设备的过程中，最重要的事情之一是能够利用易受攻击的二进制文件，使用**返回导向编程**（**ROP**）等技术，这正是我们将在本节中讨论的内容。

我们需要这种技术的原因是，在利用过程中，我们经常需要将最终结果作为 shell 或执行后门，这可以为我们提供额外的信息或访问敏感资源。

ROP 的概念在 ARM 和 MIPS（甚至 x86）中是相同的；然而，我们需要记住一些平台级别的差异。简单来说，ROP 涉及从各个位置拾取特定指令（小工具），并将它们链接在一起构建完整的 ROP 链，以执行特定任务。

# 准备工作

如前所述，要执行 ROP，我们需要能够识别可以链接在一起的有用 ROP 小工具。要找到这些特定的小工具，我们可以手动查看 libc 或其他库中的各个位置，或者使用自动化工具和脚本来帮助我们完成相同的工作。

为了简化问题，我们将以 ARM 上的易受攻击程序为例，并稍后查看一些其他示例，以帮助我们加深对基于 ROP 的利用的理解。

我们需要的一些组件如下：

+   **GDB-Multiarch**：各种架构的 GDB

+   **BuildRoot**：用于为 ARM 架构编译我们的易受攻击程序

+   **PwnDbg**：这是帮助利用的 GDB 插件

+   **Ropxx**：这是帮助我们组合 ROP 小工具并构建最终链的 Python 脚本

目前我们不打算使用任何自动化工具，而是专注于手动方法，以便理解基本原理。如果您以后想使用自动化工具（我建议这样做），您可以查看*另请参阅*部分，了解一些有用的链接。

# 操作步骤

在本节中，我们将看看如何开始利用 ARM 环境中的简单堆栈缓冲区溢出。

1.  在这种情况下，易受攻击的程序如下：

```

#include <stdio.h> 
#include <stdlib.h> 
void IShouldNeverBeCalled() 
{ 
puts("I should never be called\n"); 
exit(0); 
} 
void vulnerable(char *arg) 
{ 
char buff[10]; 
strcpy(buff,arg); 
} 
int main(int argc, char **argv) 
{ 
vulnerable(argv[1]); 
return(0); 
} 
```

正如您在前面的程序中所看到的，`main`函数接受用户提供的输入，然后将该参数传递给具有 10 字节缓冲区（名为 buff）的易受攻击函数。如预期的那样，如果输入参数的大小显着大于 buff 的大小，就会导致溢出。

一旦溢出了 buff，我们需要找到一种方法来覆盖`pc`或`lr`寄存器，以控制程序执行流。这可以通过在`strcpy`地址设置断点，然后分析复制前后的堆栈来完成。

1.  让我们首先使用 Qemu 仿真运行这个程序，用于 ARM 架构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f923203f-f2e3-4220-af7f-082226249514.png)

我们还添加了`-g`参数，以便将调试器附加到运行的实例上，这里是端口`12345`，现在我们可以使用 GDB 连接，如下所示。

1.  我们将在这里使用 GDB-multiarch，然后指定 sysroot 和远程目标，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a453c807-b295-4515-b153-58670f379b82.png)

让我们在 main 处设置一个断点（b main）并继续（c）程序。

现在来看寻找 gadgets 的有趣部分。要找到有用的 gadgets，我们需要寻找一些指令，这些指令允许我们设置某些值，我们可以跳转到这些值，比如说 system（在我们当前的情况下），同时在跳转时，将地址作为`/bin/sh`的参数，这将给我们提供 shell。

这意味着我们可能需要将`system`的地址放在`pc`或`lr`中，将`/bin/sh`的地址放在`r0`中，这是 ARM 中的第一个寄存器，也是作为被调用函数的参数。一旦我们找到了允许我们执行所有这些操作的指令，我们还需要确保在我们之前提到的有用指令之后的指令中有一个这些内容，即要么跳转到我们控制的地址，要么`pop {pc}`或`pop {lr}`。

1.  如果我们查看`libc`中存在的函数之一`erand48`的反汇编，我们可以看到它具有一组特定的有用指令，这些指令允许我们控制执行并设置寄存器的值。如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e8958a75-fe9e-4aba-9388-cd0f9f88596e.png)

以下是我们感兴趣的三条指令：

1.  1.  `lmd sp, {r0, r1}`：此指令从堆栈中加载`r0`和`r1`的值。这将用于控制`r0`，它作为我们即将跳转到的函数（system）的参数。

1.  `add sp, sp, #12`：此指令简单地将堆栈指针增加`12`。

1.  `pop {pc}`：此指令从堆栈中弹出值并将其放入`pc`，这意味着我们将能够控制程序的执行。

现在我们需要找到两件事，它们分别是：

1.  1.  `system`的地址。

1.  1.  `/bin/sh`的地址。

1.  我们可以使用`print`命令或使用`disass system`找到`system`的地址，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b0a19344-b3eb-4fd8-83c1-c1d532ca99a3.png)

1.  现在，让我们生成一个 50 个字符的循环字符串，并看看我们如何溢出缓冲区以成功跳转到`errand48`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/790b6335-21ee-4418-badf-395aeb5805a6.png)

1.  让我们使用生成的字符串调试程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ff91c4d0-3d74-4b23-bdd3-97393858776d.png)

1.  现在我们将在易受攻击的函数处设置一个断点并继续执行。GDB 将触发断点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/aade2565-8feb-42a0-9db2-2fdff0ec66dd.png)

1.  让我们也在易受攻击的函数的最后一条指令处设置一个断点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/895ce702-a883-4cd2-8984-872d25808228.png)

1.  一旦断点被触发，让我们分析一下堆栈：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9257c1d1-8390-4d32-821f-e5df160123c2.png)

突出显示的指令将从堆栈中弹出两个双字（double words），分别放入`fp`和`pc`。如果我们在这里查看堆栈中的第二个值，它是`0x61616165`（'eaaa'），这意味着这个值将放入`pc`。

1.  如果我们查看此值的偏移量，我们将能够找出如果我们想要用我们期望的地址覆盖`pc`，偏移量将是多少个字符。我们可以使用`cyclic` `-l 0x61616165`来找到这个值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/55877aa0-d6e0-41af-8894-9b8413cb8ec8.png)

1.  这意味着我们需要以小端格式将我们期望的`pc`值（`erand48`的`ldm`指令）放在偏移量为 16 的位置。

我们可以使用以下 Python 代码生成新的字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c955cc3e-b427-4da4-a652-6de82d8c106e.png)

1.  接下来，我们可以重新运行生成的字符串，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b387db38-5b7f-4808-8411-347674db7c27.png)

1.  在这个阶段，像之前一样附加 GDB。在易受攻击的函数的最后一条指令的地址`0x84e0`上设置断点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/b98021d4-b4c9-467c-bcfb-f3ba13fa7a8f.png)

1.  这一次我们可以看到`pc`被加载到`erand48`指令的地址`0x4087b9dc`。让我们使用`ni`步进一条指令，达到`ldm`指令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/dacc9ae1-2b73-4594-bb4c-5852142711b9.png)

1.  正如我们在这一步看到的，寄存器`r0`加载了`0x61616161`，这是我们想要放置`/bin/sh`字符串地址的寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6d6a4fb1-9cb7-4831-9847-ff3afcf4fbf5.png)

1.  有效的偏移量将是*16 + 4 + 0 = 20*，如下所示：

```
 "A"*16 => 16 bytes 
 "\xdc\xb9\x87\x40" => 4 bytes
```

1.  因此，在偏移量 20 处，我们需要放置`/bin/sh`字符串的地址，然后将其作为参数传递给系统。通过两次步进，我们可以到达 pop，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9fb9b1f6-50d0-49f7-aa33-cc8967718ff7.png)

1.  `pc`将获得值`0x61616164`，偏移量可以用与之前相同的方式计算：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2ff96be0-6be7-4173-835c-6681bc305cd7.png)

1.  因此，`pc`的有效偏移量将是：

*16 + 4 + 0 + 12 = 32*

这意味着在偏移量 32 处，我们需要放置系统的地址，这是我们之前找到的。

另外，让我们继续在偏移量 36 处放置`/bin/sh`的 ASCII 字符串，并在偏移量 20 处引用它。因此，栈上字符串的地址将是`0x407fff18`。

1.  我们可以使用`ropgen`模块来生成利用字符串，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ab5e3be6-f1b0-47e9-844a-6c94bc0bbf5a.png)

1.  让我们再次调试并执行一遍：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/69ceeee0-4890-42a4-8f3e-bdd7a60e7d03.png)

1.  如果我们现在查看栈，ASCII 字符串`/bin/sh`现在位于地址`0x407fff38`，这意味着我们需要调整我们的代码以反映这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/441da483-a57b-446f-a5c4-a5b15ced8af3.png)

1.  通过与之前相同的方式调试，我们可以看到这一次我们的 ASCII 字符串被加载到了正确的地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/933b13f7-c07a-4b83-b103-d44cbb6965a5.png)

1.  我们可以再次步进到达`erand48`地址，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2e5e9c80-8d99-40c4-9e36-8474fd966aa6.png)

1.  这一次寄存器`r0`存储了所需的 ASCII 字符串的地址。通过两次按**c**来到达函数的最后一条指令（pop pc），如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e911f0e7-93cf-4906-9c8c-0420d0cf539f.png)

1.  `pop {pc}`将从栈中加载系统的地址并将其放入`pc`，然后将带有我们`/bin/sh`字符串地址的`r0`传递给系统。我们可以查看 regs 来确认这一点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/51562d9d-cf40-4b10-927f-adc7a41b5cde.png)

1.  一旦我们按下`c`，我们将能够获得一个 shell，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/bfddccc7-2162-49bb-a85a-679fe0c5ad95.png)

因此，我们能够利用基于堆栈的缓冲区溢出，并使用 ROP 跳转到系统，并使用我们期望的字符串作为参数，利用`erand48`函数中的指令，最终获得一个 shell。

然而，这只是一个在基于 ARM 的架构上开始使用 ROP 的非常简单的例子。类似的技术可以应用于 MIPS 上的 ROP，如下所示。我们在这里展示的另一件事是如何解决缓存不一致的问题，这通常在利用过程中出现。

1.  我们在这种情况下寻找的易受攻击程序是来自 DVRF 固件的`socket_bof`。在这种情况下，我们将要跳转到的第一条指令是`sleep`，并提供我们想要休眠的时间作为参数。我们调用`sleep`来刷新缓存，然后稍后准备我们的小工具，以调用系统并将命令地址作为参数，如下所示。下面的截图显示了我们的第一个小工具的样子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5d50b447-9879-4033-aceb-492f3f997d73.png)

正如我们所看到的，通过这个小工具，除了设置`$a0`之外，这是第一个寄存器（就像 ARM 中的`r0`一样），我们还能够控制**返回地址**（**RA**）和一些其他寄存器，比如`$fp`，`$s7`，`$s6`...`$s0`，最后跳转到`$ra`。

1.  在下一个小工具中，我们将准备使用已经设置的`$a0`值跳转到`sleep`。请注意，在这个小工具中，`$t9`正在从我们在前一个小工具中能够控制的`$s0`中获取值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f08807eb-ef79-4436-b0f1-d23f24259a9e.png)

1.  一旦我们设置好这个小工具，下一个小工具将设置系统参数（我们要执行的字符串命令的地址），并允许我们跳转到系统。在这种情况下，参数是`$sp+24`，而`$t9`（我们要设置为系统地址）从`$s3`中获取其值，而我们在前面提到的第一个小工具中能够控制`$s3`。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/78c5d533-c622-4599-a82d-a14c611d871d.png)

1.  一旦我们把所有的小工具都放好，下一步显然是计算各种偏移量，以确保我们的 ROP 链能够正常工作。整个 ROP 链看起来就像下面截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/3b7c6f10-29f5-449f-8cd6-9b912d0e83ed.png)

1.  接下来，将各个参数放在正确的位置，运行二进制文件，并从`/proc/maps`中找出`libc`地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2cacb017-45cd-481d-a56a-c6f2a1d76709.png)

1.  一旦正确识别了`libc`地址并且程序运行起来，您应该能够看到我们的参数现在在运行时放在了正确的地址，可以使用 GDB 进行确认：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6e76df9c-cebc-4ad0-86bd-16a0b0beb754.png)

在上面的截图中，`id`就是我们想要执行的命令。

1.  总之，在这种情况下，我们的 ROP 链看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/52f3fe0b-b46e-4195-a08b-61663ed82c48.png)

这就是 ROP 利用的全部内容，我们将介绍 ARM 和 MIPS 的示例。在现实世界的场景中，应用是一样的——可能不仅仅是几条指令，你需要一些指令来形成你的 ROP 链。

# 另请参阅

您可以查看一些自动化工具，这些工具将帮助您在各种平台上进行基于 ROP 的利用过程。建议您查看的一些工具如下：

+   ROPGadget: [`github.com/JonathanSalwan/ROPgadget`](https://github.com/JonathanSalwan/ROPgadget)

+   MoneyShot: [`github.com/blasty/moneyshot`](https://github.com/blasty/moneyshot)

# 链接 Web 安全漏洞

当对手针对某种 IoT 设备时，通常会利用多个漏洞来武装攻击。这些漏洞本身可能在严重性上较低；然而，当结合在一起时，攻击的影响就会更大。多个低级漏洞组合成一个严重漏洞并不罕见。这在 IoT 设备方面尤为重要。在 IoT 设备中发现的一个严重漏洞可能会危及设备的完整性。本文将介绍如何将 Web 安全漏洞链接在一起，以在没有钥匙、车钥匙或凭据的情况下访问 Subaru 连接的车辆。

任何漏洞研究都必须在合法范围内进行。对 MySubaru 账户和 Subaru 服务器进行未经授权的测试是非法的。所有测试都应该在受控环境中进行，并且应该是合法拥有的。尽管 Subaru 远程服务不能控制发动机和传动系统功能，但测试结果是未知的。本文中的所有严重漏洞都已被 Subaru 报告并解决。

# 如何做到这一点...

进行任何评估的第一步是威胁建模；在这种情况下，从黑盒的角度对 2017 年 Subaru WRX STi 连接车辆进行威胁建模。首先确定车辆的入口点，这将提供一个已识别的攻击面，可以在此基础上构建。

# 步骤 1 - 确定资产和入口点

每辆车都不同，有些型号比其他型号拥有更多的功能。研究 Subaru 连接车辆和不同型号和年份之间的功能之间的公开资源。例如，我们知道连接车辆可以通过蜂窝 4G/LTE 连接访问互联网，但其他车辆可能通过手机连接或其他方式（如 Wi-Fi）获得互联网访问。让我们从这里开始，在执行任何主动攻击阶段之前记录我们对目标车辆的了解：

+   **蜂窝连接**：Subaru 连接车辆通过 AT&T 4G LTE 连接到互联网（[`about.att.com/story/att_subaru_bring_4G_lte_to_select_model_year_vehicles.html`](http://about.att.com/story/att_subaru_bring_4G_lte_to_select_model_year_vehicles.html)）。

+   **Wi-Fi**：目标 Subaru 车辆中没有 Wi-Fi。

+   **蓝牙**：车载娱乐系统通过蓝牙连接设备，以访问媒体、设备通讯录和消息。

+   **钥匙链**：要进入和启动这辆特定的车辆，需要钥匙链。钥匙链在 314.35-314.35 MHz 的频率范围内传输（[`fccid.io/HYQ14AHC`](https://fccid.io/HYQ14AHC)）。

+   **USB 连接**：车载娱乐系统使用 USB 连接设备的媒体以及 GPS 和车载娱乐系统本身的更新。

+   **SD 卡**：车载娱乐系统有一个 microSD 卡插槽用于 GPS 地图。

+   **OBD II**：用于访问 CAN 总线进行诊断，并可以在车辆上刷写 ECU 图像以进行调整或其他性能修改。

+   **CAN 总线**：每辆车都有一个或多个 CAN 总线用于车内通信。CAN 总线本身是容易受到攻击的，可以使用免费工具进行嗅探。

+   **移动应用程序**：Subaru 的 Starlink 车载技术连接到 MySubaru 应用程序，允许您远程锁定和解锁车辆，访问您的喇叭和灯光，查看车辆健康报告，并在地图上找到您的车辆。要使用这些功能，必须购买订阅。

+   **网络应用程序**：除了 MySubaru 移动应用程序外，Subaru 的 Starlink 车载技术连接到一个网络界面，允许您远程锁定和解锁车辆，访问您的喇叭和灯光，更改用户设置，安排服务，添加授权用户，并在地图上找到您的车辆。要使用这些功能，必须购买订阅。

现在我们已经列出了连接车辆的入口点，我们对首要攻击目标有了更好的了解。我们还可以根据我们的技能和舒适度来评估努力的程度。

# 步骤 2 - 找到最薄弱的环节

对车载娱乐系统和 CAN 总线的研究已经很多。在蓝牙、Wi-Fi 或钥匙链中发现的任何协议漏洞可能会变成一个零日漏洞，并需要相当长的时间。话虽如此，让我们把注意力转向 MySubaru 移动应用程序和网络应用程序。对于移动和网络应用程序，与车辆的接近并不是必要的。所需的只是一个 STARLINK Safety Plus 和 Security Plus 订阅，支持的车型和 MySubaru 账户的凭据。这很好，因为我们可以同时处理这三个应用程序。此外，Subaru 已经委托通过其移动和网络应用程序解锁、锁定、按喇叭和定位车辆。目标应用程序是 MySubaru Android 和 iOS 应用程序的 1.4.5 版本。发现的任何应用程序级别的漏洞可能会产生高级别的影响，也可能对 Subaru 车主构成安全问题。

# 步骤 3 - 侦察

由于我们将精力集中在应用程序上，我们需要对所有三个应用程序进行一定程度的侦察。让我们先从移动应用程序开始，然后再转向网络应用程序。

# 安卓应用程序

在执行动态测试之前，Android 应用程序很容易进行静态拆解和分析。反向 Android 应用程序需要一定程度的努力，但如果我们能发现低 hanging fruit，那么我们就能轻松获胜。我们首先需要通过第三方市场获取 MySubaru 应用程序，并确保它与 Google Play 版本相同。验证后，应采取以下步骤对 MySubaru Android 应用程序进行基线侦察：

+   使用 MobSF 或类似工具拆解 APK：

+   分析类和方法

+   识别第三方库

+   确定应用程序是原生的还是混合的

+   寻找硬编码的值

+   寻找潜在的秘密和环境

+   安装应用程序并监视 Android 组件

+   活动、服务和意图

+   分析数据存储

+   SD 卡使用

+   `SharedPreferences.xml`

+   缓存

+   SQLite 数据库

+   代理 Android 应用程序到车辆的所有 API 请求，使用 Burp Suite 或类似工具。

+   登录/注销

+   解锁/锁定

+   按喇叭

+   闪烁灯光

+   找到车辆

+   查看车辆健康报告

+   编辑车辆详细信息

确保为 Android 通信进行颜色编码的高亮显示和注释。这将有助于在编译用于识别 Android 漏洞的不同 API 调用时，以及其他 Subaru 应用程序时使用。

# iOS 应用程序

在反向 iOS 应用程序时，需要更多时间来获取 IPA 文件，解密它，将应用程序二进制文件传输到我们的主机计算机，然后努力找到漏洞。在这种情况下，我们必须通过 App Store 下载 MySubaru 应用程序，并执行解密和二进制传输到我们的主机计算机。完成后，应采取以下步骤对 iOS MySubaru 应用程序进行基线侦察：

+   使用 Hopper 或类似工具拆解 iOS 二进制文件：

+   分析类和方法（使用 Class-dump-z）

+   识别第三方库

+   确定应用程序是原生的还是混合的

+   寻找硬编码的值

+   寻找潜在的秘密和环境

+   安装应用程序并监视 iOS 组件：

+   通过 URL schemes 进行 IPC

+   分析数据存储：

+   Plists

+   SQLite 数据库

+   Cache.db

+   本地存储

+   代理 iOS 应用程序到车辆的所有 API 请求，使用 Burp Suite 或类似工具：

+   登录/注销

+   解锁/锁定

+   按喇叭

+   闪烁灯光

+   找到车辆

+   查看车辆健康报告

+   编辑车辆详细信息

应该注意 iOS 和 Android API 调用之间的差异。数据存储也应该注意，重点放在个人详细信息和凭据上。应根据对两个应用程序执行的侦察来确定潜在的障碍。例如，两个移动应用程序都通过`POST`请求发送远程服务调用，其中包含一个`sessionId`参数值，对于每个请求都是唯一的。

这可能会妨碍我们伪造远程服务请求的能力，因为这个值是唯一的，而不是硬编码的值。在 iOS 应用程序中发现的一个关键观察是将所有 HTTP 请求和响应缓存到`Cache.db` SQLite 数据库中。`Cache.db`中的所有数据都是明文，包括车辆详细信息、个人所有者详细信息、帐户令牌和 API 请求，攻击者可以在备份 iOS 设备或使用 iFunbox 等免费工具时提取这些数据。

以下截图显示了 URL 中带有`handoffToken`令牌的缓存请求：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/67d4eb47-993a-4b9e-b148-443ab09c1158.png)

# 网络应用程序

接下来，我们将查看 MySubaru 网络应用程序，并检查所有 HTTP 请求和响应。MySubaru 网络应用程序包含移动应用程序没有的其他选项，例如添加授权用户或更改帐户 PIN 码。代理网络应用程序流量时，应确保点击和分析所有状态配置更改，例如以下列出的更改：

+   登录/注销

+   锁定/解锁

+   按喇叭

+   闪烁灯光

+   找到车辆

+   查看车辆健康报告

+   编辑车辆详细信息

+   添加车辆

+   添加和删除授权用户

+   更改 PIN

+   更改密码

+   更改安全问题

+   更改个人账户详情

应该注意网络应用程序和移动应用程序之间的所有差异。到目前为止，网络应用程序和移动应用程序之间的一个主要区别是远程服务 API 请求如何发送到 Subaru 服务器。API 端点对所有应用程序保持不变，如果我们发现漏洞可以利用，这将是有用的。

以下屏幕截图显示了 Burp Suite 中所有应用程序的 HTTP 历史记录，并进行了颜色编码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/42b354f1-a899-4f38-96b3-b7318530ac8c.png)

# 第 4 步 - 识别漏洞

在我们的 Web 代理中记录了所有应用程序功能和 API 调用后，我们现在可以开始识别设计中的漏洞，并测试逻辑缺陷以寻找漏洞。以下是观察到的漏洞列表：

1.  网络应用程序通过 URL 发送所有远程服务调用，作为`GET`请求，而移动应用程序则将远程服务调用作为`POST`发送，参数在请求体中。在网络应用程序中没有随机生成的`sessionIds`用于执行远程服务调用。

1.  移动应用程序没有强制证书固定和验证。

1.  iOS 应用程序的所有请求和响应都被缓存。

1.  账户配置更改，如编辑车辆详情或添加授权用户，不包含反 CSRF 令牌。

1.  当添加授权用户时，所有者不会收到通知。

1.  账户 PIN 的更新不需要知道先前设置的 PIN。

1.  安全问题的更新不需要重新身份验证，没有最小字符长度，并且可以都是相同的值，如 1。

1.  授权用户对 Subaru 远程服务拥有完全访问权限，并且没有添加限制。

1.  所有应用程序都没有并发登录策略。

以下是不需要身份验证或先前了解设置即可进行更改的 PIN 和安全问题更新配置部分的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6c7f1627-47fb-466e-ada1-a326df8db7e9.png)

现在我们可以开始更改反映用户输入到屏幕的配置参数值。由于我们未被授权在此情况下发送恶意有效负载，所有努力将是手动的，并且参数将通过 Burp Suite 的重放器手动输入。考虑到这一点，我们可以尝试基本的 XSS 有效负载，并观察是否存在任何验证和/或编码。首先想到的反映我们参数值的位置是车辆昵称。似乎一个普通的`<script> alert(1)</script>`可以在浏览器中执行。

这现在是一个经过身份验证的**跨站脚本**（**XSS**）漏洞，可能对我们有用（漏洞＃10）。以下是 XSS 的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/40887edf-f1ec-44d2-a32c-cd236099b297.png)

接下来，我们可以检查其他 API 逻辑缺陷，例如是否执行了速率限制，或者 API 请求是否可以在不修改的情况下重放。这可以通过将 HTTP 请求发送到 Burp Suite 的重放器并重放请求来完成。我们将发现在进行远程服务调用时没有重放或速率限制安全控制（漏洞＃11）。尽管在 API 请求之间需要一个短暂的 5 秒间隔，以便车辆执行请求。

另一个要测试的逻辑缺陷是移动应用程序和 Subaru 服务器之间的登录过程。Subaru 通过`POST`主体传递用户凭据，然后在验证后将用户重定向到其帐户仪表板。在登录过程中，账户凭据成功验证后，将向 Subaru 的服务器发送一个`GET`请求，其中包括用户名、handoffToken 和其他参数。这是在 iOS 应用程序的`Cache.db`中找到的相同 HTTP 请求，但令牌值不同。这个`GET`请求可以被复制并粘贴到浏览器中，并且可以自动登录到 MySubaru 账户，而无需用户名或密码（漏洞＃12）。此外，handoffToken 永远不会过期，即使 MySubaru 用户注销了网络和移动应用程序，它仍然有效。即使更改密码也不会使此令牌过期。这是一个很好的发现，因为我们现在可以在车主不知情的情况下持久访问 MySubaru 账户。与 handoffToken 相关的另一个问题是为新设备和已授权用户创建新令牌，这些用户登录其 MySubaru 移动应用程序。例如，所有者使用两部 iPhone 和两部 Android 设备登录其 MySubaru 账户。现在有四个活动的 handoffToken。这也适用于已授权用户。例如，两个已授权用户（`carhackingemail@gmail.com`和`carhackingemail1@gmail.com`）使用三个设备登录其 MySubaru 移动应用程序。现在已授权用户有六个活动令牌，这扩大了对一个 MySubaru 账户的攻击面。以下是一个示例，显示了两个已授权用户账户`carhackingemail@gmail.com`和`carhackingemail1@gmail.com`，它们使用三个不同的移动设备并获得了不同的 handoffToken 值：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/eb7d4b3d-7c46-45bc-bac5-bdcd343dfcdc.png)

# 第 5 步-利用-链接漏洞

通过被动和主动分析已经确定了至少 11 个漏洞。一些漏洞可以直接利用，而其他一些可能间接利用，因为应用程序的逻辑和设计。为了访问车辆而无需钥匙、车钥匙或凭据，我们应该有所需的东西。

通过查看已识别的安全漏洞，需要用户干预才能成功利用 MySubaru 所有者的账户和车辆。我们可以通过几种方式来做到这一点。我们可以尝试以下攻击场景，这依赖于一种社会工程学形式：

+   制作一个恶意页面，其中包含用于车辆昵称的 XSS 有效负载

+   获取 handoffToken 以获得有效的会话

+   通过 CSRF 添加已授权用户

+   通过 CSRF 伪造解锁远程服务调用目标 Subaru 车辆

+   更改安全问题

+   更改 PIN

+   赚钱$$

可以用于获得有效的`handoffToken`的其他攻击场景包括：

+   受害者使用攻击者设备登录，可以从缓存中提取令牌

+   受害者将移动设备（Android/iOS）备份到攻击者的计算机上，攻击者将受害者的备份还原到包含 handoffToken 的测试移动设备中

+   攻击者窃取已授权用户的令牌而不是车主

+   通过 Wi-Fi 热点或其他方式进行中间人攻击

+   通过 iFunBox 获取`Cache.db`（iOS）

+   审计日志通过`URL GET`请求泄漏 handoffToken，可以被 Subaru 的系统管理员、检查网络流量的企业网络管理员和无线热点获取

攻击者不仅可以未经授权地访问车辆，还可以跟踪车主并将其安全置于危险之中。还可以探索其他后利用场景，例如以下内容：

+   窃取车辆内的内容

+   破坏车辆的引擎

+   保持对 MySubaru 账户的持久性，该账户可能有多辆车辆

+   植入带外跟踪器

+   植入恶意 Wi-Fi 接入点 w/GSM，以远程连接来利用附近的接入点或车辆

+   重放远程服务请求，如锁定车辆以耗尽电池

您可能已经注意到，这些都是基本的网络安全漏洞，而不是突破性的零日漏洞利用。对于利用基本漏洞的影响，对于物联网连接的设备和车辆来说要高得多。

# 另请参阅

访问以下网页，阅读本配方中讨论的研究：

+   [`www.scmagazine.com/researcher-hacks-subaru-wrx-sti-starlink/article/666460/`](https://www.scmagazine.com/researcher-hacks-subaru-wrx-sti-starlink/article/666460/)

+   [`www.bitdefender.com/box/blog/iot-news/researcher-finds-basic-mistakes-subarus-starlink-service/`](https://www.bitdefender.com/box/blog/iot-news/researcher-finds-basic-mistakes-subarus-starlink-service/)

+   [`www.databreachtoday.com/exclusive-vulnerabilities-could-unlock-brand-new-subarus-a-9970`](http://www.databreachtoday.com/exclusive-vulnerabilities-could-unlock-brand-new-subarus-a-9970)

# 为固件配置持续集成测试

为 C/C++编写的固件构建可能对具有复杂 Makefile 的传统产品构成挑战。然而，在部署生产构建之前，所有源代码都应该进行静态分析，以检测安全漏洞。本配方将展示如何在持续集成环境中为固件配置基本的 C/C++静态分析。

# 准备工作

对于本配方，我们将使用以下应用程序和工具：

+   **Jenkins**：这是一个开源的构建自动化服务器，可以定制运行质量和安全代码分析。Jenkins 可以通过以下链接[`jenkins.io/download/`](https://jenkins.io/download/)下载。根据操作系统的不同，有各种安装 Jenkins 的方法。对于 Debian 和 Ubuntu，可以使用以下命令安装 Jenkins：

```
wget -q -O - https://pkg.jenkins.io/debian-stable/jenkins.io.key | sudo apt-key add -

```

+   将以下行添加到`/etc/apt/sources.list`：

```
deb https://pkg.jenkins.io/debian-stable binary/
sudo apt-get update
sudo apt-get install jenkins

```

+   **Fuzzgoat**：这是一个易受攻击的 C 程序，可以通过以下 GitHub 存储库[`github.com/packttestaccount/fuzzgoat`](https://github.com/packttestaccount/fuzzgoat)下载。使用以下命令将 fuzzgoat 应用程序克隆到您的 Jenkins 构建服务器中：

```
 git clone https://github.com/packttestaccount/fuzzgoat.git

```

+   **Flawfinder**：这是一个简单的工具，用于分析 C/C++代码中的潜在安全漏洞。Flawfinder 可以通过以下链接[`www.dwheeler.com/flawfinder/flawfinder-2.0.4.tar.gz`](https://www.dwheeler.com/flawfinder/flawfinder-2.0.4.tar.gz)下载。

通过 pip 简单安装 Flawfinder 的方法如下：

```
pip install flawfinder

```

# 如何做…

要设置固件的持续集成测试，请使用以下步骤创建您的环境。

1.  安装了 Jenkins 后，登录并单击“新建项目”：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/aba628cc-7a9d-4a5d-8a1a-3e7dda6226be.png)

确保您的`JAVA_HOME`环境变量已配置。如果使用了多个 Java 版本，请确保通过 Jenkins 的全局工具配置在`http://127.0.0.1:8080/configureTools/`中配置 JDK。

1.  输入名称并选择自由风格项目：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5648c9e9-2ea8-4210-8aae-c83954e4ae52.png)

1.  配置页面将出现。暂时不要输入任何设置，因为我们将在构建项目后加载一个本地项目到 Jenkins 将创建的工作空间中。构建将失败，这没关系，因为我们只是希望 Jenkins 创建目录，然后我们将把我们的 C 代码项目文件复制到工作空间中。这一步也将用于以下配方中创建工作空间：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/def1200a-f377-42fb-8971-170b782f80de.png)

1.  单击保存按钮后，Jenkins 将重定向您到项目页面，我们将选择“立即构建”：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/089dca88-628d-4283-a34e-9ed6a26bf8e2.png)

现在，Jenkins 已经构建了我们的工作空间，我们可以在其中传输我们的代码文件。目录结构因所使用的操作系统而异。对于 Ubuntu，工作空间文件位于`/var/lib/Jenkins/workspace/`，对于 OS X，工作空间文件位于`/Users/Shared/Jenkins/Home/workspace/`。将 fuzzgoat 文件传输到新创建的工作空间目录中，该目录以项目名称命名。在这种情况下，它是`/var/lib/Jenkins/workspace/PacktTestFirmware/`。

确保 Jenkins *Nix 用户具有适当的文件和文件夹权限，以扫描`workspace`目录中的任何内容。这还包括工具扫描相关目录的权限。

1.  现在 fuzzgoat 在 Jenkins 工作空间目录中，返回 Jenkins 构建项目并添加一个构建步骤来执行一个 shell 命令，该命令将在我们的`workspace`目录中执行`flawfinder`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/5cf6a9c6-356e-4ffd-9eea-900ee77c4577.png)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4228b997-8122-4ad3-82d7-6a7814dbc73f.png)

1.  添加另一个构建步骤来执行另一个 shell 命令。这将在基于 fuzzgoat 提供给我们的 Makefile 的工作目录中执行`make`命令。之后单击保存：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/dc55c928-9720-41f0-b89f-a42a27ab1622.png)

1.  在项目页面中选择立即构建选项。单击永久链接箭头，然后选择控制台输出，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/c9fef50d-f8a2-4110-92f2-399fee2c3313.png)

1.  接下来的页面应该显示构建和`flawfinder`的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/6477d128-7fd5-44ce-befe-e6b47ac8c5f7.png)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/478cc1d4-8bec-4476-9263-7c90351f4105.png)

构建步骤可以定制以警报工程或安全经理根据结果执行操作。但是，并非所有来自`flawfinder`的命中都是漏洞，但应该对其进行审查，以确保没有引入软件安全漏洞。请记住，`flawfinder`是一个简单的工具，提供了最少量的 C/C++代码检查。它只是检查常见的缓冲区溢出问题和其他众所周知的问题，比如使用被禁止的函数。商业 SAST 工具包括依赖图以及调用图，以检查依赖软件漏洞和应用程序数据流。此外，许多商业 SAST 工具还包括 IDE 插件，用于实时检查软件安全漏洞。对于 C/C++，XCode 的 Clang 静态分析器有免费的 IDE 插件；但是，在 OS X 环境中编译此类代码需要自定义配置。Clang 不会分析无法编译的文件。在配置移动应用程序的持续集成测试部分，我们将讨论如何使用 IDE 插件来静态分析代码。

# 另请参阅

有关 Clang 静态分析器的更多信息，请访问以下链接：

+   [`clang-analyzer.llvm.org/`](https://clang-analyzer.llvm.org/)

+   [`help.apple.com/xcode/mac/9.0/#/devb7babe820`](https://help.apple.com/xcode/mac/9.0/#/devb7babe820)

有关各种编程语言的更多源代码分析工具列表，请参阅以下网址：

+   [`www.owasp.org/index.php/Source_Code_Analysis_Tools`](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)

# 为 Web 应用程序配置持续集成测试

无论物联网设备使用 Web 应用程序还是 Web 服务进行消息传递，其代码都应该进行静态和动态分析，以查找软件安全漏洞。在这个示例中，我们将演示如何在生产部署之前配置 Web 应用程序构建的动态扫描。

# 准备工作

在这个示例中，我们将使用 Jenkins 作为我们的自动化构建服务器，OWASP ZAP 作为我们的动态扫描器。我们将使用 OWASP ZAP Jenkins 插件和可以通过以下链接下载的 OWASP ZAP 工具：

[`github.com/zaproxy/zaproxy/wiki/Downloads`](https://github.com/zaproxy/zaproxy/wiki/Downloads)。

# 如何做...

要为 Web 应用程序设置持续集成测试，请使用以下步骤创建您的环境。

1.  首先，我们需要下载 OWASP ZAP 插件，可以通过 Jenkin 的插件管理器完成，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/20926133-8feb-44e6-906c-9799e3cc9938.png)

OWASP ZAP 插件下载

1.  然后 Jenkins 将重新启动。重新登录 Jenkins，我们将致力于配置 ZAP。在 Jenkins 中使用 ZAP 有两种方法。一种是使用加载的会话运行 ZAP，另一种是设置 Selenium 来执行 ZAP 并在之后保持会话。我们将设置 ZAP 以加载会话来运行我们的目标构建。为此，我们首先需要通过`http://127.0.0.1:8080/`configure 配置 ZAP 设置和环境变量。在这种情况下，设置 ZAP 主机和端口号如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/26bd354b-cba8-4360-9e77-d850f2e52bc8.png)

可以配置多个 ZAP 主机以允许多个并发构建扫描。这可以在各个项目的构建步骤中配置，这将覆盖系统设置。

1.  根据正在使用的操作系统（[`github.com/zaproxy/zaproxy/wiki/FAQconfig`](https://github.com/zaproxy/zaproxy/wiki/FAQconfig)），插入 ZAP 的默认目录。以下是 ZAP 在 OS X 上使用的默认目录：

如果您使用 ZAP 的每周版本，请使用`/Users/<user>/Library/Application\ Support/ZAP_D/`。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/411a6ca4-44f6-41e9-b74b-2c49d9b01221.png)

1.  现在，创建一个自由风格项目，就像我们在之前的配方中所做的那样，并适当命名它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/dc296661-1e1e-44aa-bc65-4766b586f6b4.png)

1.  保存项目并选择立即构建，以便 Jenkins 创建我们的项目工作空间，就像之前的配方一样。

由于我们将使用加载的会话执行 ZAP，我们必须创建一个会话并将其保存在项目工作空间目录中。为此，请导航到正在运行的目标应用程序构建，并通过浏览器将应用程序流量代理到 ZAP。确保点击所有链接，并爬行页面并执行应用程序功能。在以下示例中，我们正在使用在本地端口`8888`上运行的 The BodgeIT Store，并通过导航到文件|持久会话...将会话保存到项目工作空间中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/f3e60316-e57c-4099-ad7b-88586770bc04.png)

1.  在我们项目的 Jenkins 工作空间目录中保存会话。在这种情况下，如下截图所示，在工作空间项目目录中的 PacktZAPscan：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/05038cb4-2588-458d-9ca6-254edd0c96b3.png)

PacktZAPscan 在工作空间项目目录中

1.  在 ZAP 中，让我们配置 ZAP 的 API 密钥。转到工具菜单并打开选项页面。在选项中，选择 API 部分，并插入由 Jenkins 插件提供的默认`ZAPROXY-PLUGIN`密钥，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a8469828-810b-40d4-be41-b7dd2d4b872f.png)

请注意，此 API 密钥可以完全禁用，或者在创建构建步骤时通过 ZAP 插件命令行参数部分进行更改。如果 API 密钥与 Jenkins 插件 API 密钥值不匹配，则扫描将失败。

1.  有了我们在工作空间中保存的会话，返回到我们的项目并选择配置。根据应用程序架构，插入适当的源代码管理设置，构建环境和任何构建脚本。在构建部分，选择添加构建步骤|执行 ZAP：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/df0020c4-d637-4f52-8684-2215312fb8ab.png)

1.  输入 ZAP 主机设置和主目录路径，以及保存的适当会话。如果会话未保存在项目工作空间文件夹中，则会话将不会出现在加载会话下拉菜单中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/0d23107f-f887-40e2-af83-572889c22b69.png)

1.  输入会话属性，如上下文和任何身份验证凭据。上下文指的是自动扫描的范围内和范围外的目标。上下文必须是唯一的，并且不能在加载的会话中。我们可以使用构建 ID 环境变量来迭代上下文编号，使它们是唯一的，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/a71cada9-19c3-483c-a4d5-e3f7a6b49324.png)

1.  接下来的部分是攻击模式部分。在这里，我们指定目标 URL、扫描设置和可能配置并保存到项目工作区的任何自定义扫描策略。在即将到来的示例中，测试 URL 是输入的，选择了蜘蛛，并配置了一个自定义的 XSS 扫描策略。当没有指定自定义扫描策略时，将使用默认策略。配置攻击设置后，命名生成的报告，选择格式和任何导出报告设置，然后点击保存：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/8f88244a-3aeb-4db1-9b03-a434895f42ef.png)

确保权限设置正确，以便 Jenkins 和 ZAP 可以扫描您的工作区目录。

1.  然后您将被引导到项目页面。选择立即构建，然后点击构建的控制台输出。这将显示 ZAP 扫描的构建状态和进度：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e07979b7-96c9-45f9-8461-2974cce0b96d.png)

控制台输出应该类似于以下图像：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/35e46e51-cf77-4fb3-8512-d6b93f70179d.png)

控制台输出

1.  构建和扫描完成后，在工作区项目目录下的`reports`文件夹中生成报告，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4cd67bf2-8be2-4b83-90c7-3d15849b2eec.png)

1.  报告的 XML 和 HTML 版本可供查看：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/fdbccdc0-28ec-4715-bea3-e10f1ae9d71d.png)

ZAP 扫描和报告的警报可以被大量定制，只报告中等和/或高严重性的发现。扫描应该根据应用程序的架构创建上下文细节和扫描策略。例如，如果一个应用程序在 Apache web 服务器、Apache Tomcat 应用服务器和 MySQL 数据库上运行，扫描策略应该被定制为针对相应的架构环境运行检查。不建议运行默认扫描策略，因为将使用不相关的攻击，导致扫描时间过长，甚至可能耗尽 ZAP 的内部数据库资源。扫描器的好坏取决于给定的配置、规则集和策略。 

自动化扫描非常适合捕捉低挂果和可扩展性，但它们不应该取代手动的 Web 应用程序安全评估。自动扫描程序无法执行上下文业务逻辑测试，也无法智能地捕捉手动评估可以发现的未报告的发现。应该使用自动化和手动测试的组合。

# 另请参阅

要了解有关 Jenkins OWASP ZAP 插件的更多信息，请参考以下链接：

[`wiki.jenkins.io/display/JENKINS/zap+plugin`](https://wiki.jenkins.io/display/JENKINS/zap+plugin)

[`wiki.jenkins.io/display/JENKINS/Configure+the+Job#ConfiguretheJob-ConfiguretheJobtoExecuteZAP`](https://wiki.jenkins.io/display/JENKINS/Configure+the+Job#ConfiguretheJob-ConfiguretheJobtoExecuteZAP)

# 为移动应用程序配置持续集成测试

在之前的示例中，自动化分析的趋势相同，这个示例将展示如何在生产部署之前配置 Android 应用程序构建的依赖扫描和动态分析。

# 准备工作

在这个示例中，我们将使用 Jenkins 自动化构建服务器和以下工具：

+   **移动安全框架**（**MobSF**）：这是一个开源的移动应用程序静态和动态分析工具。MobSF 正在积极地为移动安全社区进行修改和开发。MobSF 可以从以下链接下载：

[`github.com/MobSF/Mobile-Security-Framework-MobSF/archive/master.zip`](https://github.com/MobSF/Mobile-Security-Framework-MobSF/archive/master.zip)

+   **OWASP Dependency-Check**：这是一个工具，用于检测项目依赖项中公开披露的漏洞，适用于多种编程语言，如 Java、NodeJS、Python、Ruby 和 Swift 等。我们将使用 Jenkins OWASP Dependency-Check 插件，该插件可以通过 Jenkins 插件管理器下载，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/e9f24b72-1ff4-4c9a-8608-674fd00e4af5.png)

+   Dependency-Check 也可以作为一个独立的工具下载，使用以下链接中描述的方法：

[`github.com/jeremylong/DependencyCheck`](https://github.com/jeremylong/DependencyCheck)

# 如何做...

要为移动应用程序设置持续集成测试，请使用以下步骤创建您的环境。

1.  首先，让我们创建一个自由风格的项目，为应用程序构建选择一个合适的名称：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4894f823-9ec9-419c-a587-04491fac48e6.png)

1.  保存并构建项目，以便我们的工作空间被创建，就像我们在早期的简单示例中所做的那样。接下来，将 Android 项目文件复制到 Jenkins 为我们创建的新工作空间中，如下面的屏幕截图所示。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ff1796ad-6e49-4759-a432-510295872968.png)

在这种情况下，我们工作空间的路径是`/Users/Shared/Jenkins/Home/workspace/PacktTestAndroid`。

1.  接下来，打开项目的配置选项，并设置构建设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/7bd19abb-6f25-44d3-b0b5-570d96e31f01.png)

1.  为您的构建环境输入任何必要的构建脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/4307a089-e17e-4657-9610-3db10bd84a69.png)

如果这是一个现有的项目，您可能已经知道构建完成后输出 APK 将被放置的位置。对于新项目，请确保您的构建编译为 APK。知道在运行构建时 APK 存储的位置是扫描构建 APK 的下一步的关键。

1.  在一个单独的窗口中，打开一个终端并导航到 MobSF 安装的位置。一旦在 MobSF 的文件夹中，运行以下命令：

```
$ python manage.py runserver
```

1.  您的终端应该看起来像下面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/1ca88dee-ff56-49a9-b0c6-65371dc2b077.png)

请注意 MobSF 的 API 密钥，因为我们需要它来从 Jenkins 构建服务器执行 REST API 调用。

当通过`clean.sh`脚本删除所有扫描和 MobSF 数据库信息时，API 密钥会更改。

1.  导航回到我们 Android 项目的 Jenkins 配置页面。添加一个构建步骤来执行一个 shell 命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/bda9bc10-a42c-407a-a841-adf581cc6a05.png)

1.  在命令区域，我们将执行 REST API 调用来上传我们构建的 APK 到 MobSF。为此，您需要拥有您的 REST API 密钥以及构建后 APK 存储的位置。使用以下命令并插入您的 API 密钥以及 API 文件路径，就像下面显示的`curl`命令一样：

```
curl --fail --silent --show-error -F 'file=@/Users/Shared/Jenkins/Home/workspace/PacktTestAndroid/app/build/outputs/apk/app-debug.apk' http://localhost:8000/api/v1/upload -H "Authorization:61ecd74aec7b36f5a9fbf7ac77494932ab5fcf4e4661626d095b5ad449746998" | awk -F'[/"]' '{print $8}' >  hash.txt  
```

这个`curl`命令上传了我们的最新构建 APK 到我们的工作空间，然后将被扫描。MobSF 创建了上传二进制文件的哈希值，这是其他 API 调用中需要引用您特定二进制文件的内容。`awk`命令只是解析 JSON 响应数据，并将哈希值插入一个文件中，以便在以后的 MobSF API 请求中调用。

1.  上传了我们的 APK 后，添加另一个构建步骤来执行一个 shell 命令，并插入以下命令，包括您的 APK 名称和 API 密钥值以扫描构建：

```
curl --fail --silent --show-error -X POST --url http://localhost:8000/api/v1/scan --data "scan_type=apk&file_name=app-debug.apk&hash=$(cat hash.txt)" -H "Authorization:61ecd74aec7b36f5a9fbf7ac77494932ab5fcf4e4661626d095b5ad449746998"
```

1.  MobSF 扫描 APK 需要几分钟的时间，因此让我们创建另一个执行 shell 构建集，并插入以下`sleep`命令：

```
Sleep 180

```

`sleep`命令可以根据 MobSF 分析您特定应用程序所需的时间进行更改。在这种情况下，大约需要两分钟。请记住，如果您等待的时间不够长，MobSF 无法扫描 APK 并尝试下载报告，那么报告将是空的。

1.  接下来，创建另一个构建步骤来生成并下载刚才提到的 PDF。插入以下命令及您相应的 API 密钥：

```
curl --fail --silent --show-error  -K hash.txt -X POST --url http://localhost:8000/api/v1/download_pdf --data  "hash=$(cat hash.txt)&scan_type=apk" -H "Authorization:61ecd74aec7b36f5a9fbf7ac77494932ab5fcf4e4661626d095b5ad449746998" -o MobSF${BUILD_ID}.pdf
```

您可以选择任何您喜欢的名称来命名 MobSF 报告。为了使报告唯一，使用了构建 ID 环境变量。Jenkins 现在应该能够从我们构建的 APK 上传、扫描、生成和下载 MobSF 报告。

1.  我们还可以添加一个构建步骤来调用 Dependency-Check，扫描我们项目的依赖项以查找已知的漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/90dc9351-907f-4714-aba9-da617647ad13.png)

1.  Dependency-Check 的扫描路径构建步骤应为空，因为工作空间目录中的项目文件将被扫描并用于在工作空间中输出结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/597283b6-d819-4d11-95ee-8bdeea28b55f.png)

确保权限正确设置，以便 Jenkins 和 Dependency-Check 可以扫描您的工作空间目录。

1.  您的项目配置构建步骤应该类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/667cc64a-b858-4e55-9d59-b67ac1130115.png)

项目配置构建步骤

1.  保存项目配置并构建 Android 应用程序。查看 Android 应用程序项目的控制台输出以查看构建进度。第一个构建步骤是构建实际的应用程序 APK，然后执行 MobSF 扫描功能，最后使用 Dependency-Check 扫描项目的依赖项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/69441c78-d460-4b65-94d4-81e8a9644df2.png)

控制台输出

1.  以下屏幕截图显示了上传和扫描 APK 的第二和第三个构建步骤：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/2724cfa3-0df8-4ea9-a304-7e3d02872dc7.png)

上传和扫描 APK 的构建步骤

1.  接下来是第四、第五和第六个构建步骤，分别执行`sleep`命令，生成 MobSF 扫描结果的 PDF，并扫描项目的依赖项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/3860df4a-7dbf-4804-9110-ca17a73e84fa.png)

1.  如果您检查项目工作空间，现在应该有一个 MobSF 报告以及一个 Dependency-Check 报告：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/9c3080d7-2d34-4238-919f-19d8c820eaa2.png)

1.  单击 MobSF 和 Dependency-Check 报告应该打开其各自格式的扫描输出（MobSF 的 PDF 格式，Dependency-Check 的 HTML、JSON、XML 格式），如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/ad6e5830-b5b4-4658-a3ce-c356776f542f.png)

扫描结果的输出

1.  以下图片是 Dependency-Check 的 HTML 报告：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/iot-pentest-cb/img/d781cf55-ea8b-48df-80e0-b5ed5dc312d5.png)

这些扫描报告可以配置为发送到集中的报告服务器，以及执行诸如发送电子邮件警报或 Jira 工单等操作，如果发现了某些严重性发现。Jenkins 具有比本章介绍的更高级功能更高度的可定制性。一个伟大的 OWASP 项目，可以帮助应用程序安全团队提高安全测试的速度和自动化程度，是 OWASP AppSec Pipeline 项目([`www.owasp.org/index.php/OWASP_AppSec_Pipeline`](https://www.owasp.org/index.php/OWASP_AppSec_Pipeline))。讨论了 AppSec 管道的各种工具和设计模式，以使小型安全团队在代码推送速度的情况下尽可能具有可扩展性和高效性。

# 另请参阅

+   Jenkins 插件 Dependency-Check 还配备了一个位置，用于存档多个应用程序依赖项以及跨应用程序使用的易受攻击组件，名为 OWASP Dependency-Track。这可以通过`http://JenkinsURL:8080/configure`在 OWASP Dependency-Track 部分进行配置。有关 OWASP Dependency-Track 的更多详细信息，请参见以下链接：

[`www.owasp.org/index.php/OWASP_Dependency_Track_Project`](https://www.owasp.org/index.php/OWASP_Dependency_Track_Project)。

+   有关 MobSF 的 REST API 的详细信息，请访问其文档页面[`github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/3.-REST-API-Documentation`](https://github.com/MobSF/Mobile-Security-Framework-MobSF/wiki/3.-REST-API-Documentation)。
