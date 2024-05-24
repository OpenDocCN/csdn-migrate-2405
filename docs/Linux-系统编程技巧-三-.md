# Linux 系统编程技巧（三）

> 原文：[`zh.annas-archive.org/md5/450F8760AE780F24827DDA7979D9DDE8`](https://zh.annas-archive.org/md5/450F8760AE780F24827DDA7979D9DDE8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用文件 I/O 和文件系统操作

文件 I/O 是系统编程的重要部分，因为大多数程序必须从文件中读取或写入数据。进行文件 I/O 还要求开发人员对文件系统有所了解。

精通文件 I/O 和文件系统操作不仅会使您成为更好的程序员，还会使您成为更好的系统管理员。

在本章中，我们将学习 Linux 文件系统和 inode。我们还将学习如何使用流和文件描述符在系统上读取和写入文件。我们还将查看系统调用以创建和删除文件，并更改文件权限和所有权。在本章末尾，我们将学习如何获取有关文件的信息。

在本章中，我们将涵盖以下内容：

+   阅读 inode 信息并学习文件系统

+   创建软链接和硬链接

+   创建文件并更新时间戳

+   删除文件

+   获取访问权限和所有权

+   设置访问权限和所有权

+   使用文件描述符写入文件

+   使用文件描述符从文件中读取

+   使用流写入文件

+   使用流从文件中读取

+   使用流读取和写入二进制数据

+   使用`lseek()`在文件内部移动

+   使用`fseek()`在文件内部移动

# 技术要求

对于本章，您将需要 GCC 编译器、Make 工具以及我们在*第三章*中的*使用 GCC 选项编写通用 Makefile*食谱中制作的通用 Makefile。*第一章*中有关安装编译器和 Make 工具的内容。

通用的 Makefile 以及本章的所有源代码示例可以从 GitHub 的以下 URL 下载：[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch5`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch5)。

我们将在 Linux 的内置手册中查找函数和头文件。如果您使用的是 Debian 或 Ubuntu，Linux 程序员手册将作为*build-essentials*元包的一部分安装，该元包在*第一章*中有所涵盖，*获取必要的工具并编写我们的第一个 Linux 程序*。您还需要安装*POSIX 程序员手册*，该手册在*第三章*中的*获取有关 Linux 和 Unix 特定头文件的信息*食谱中有所涵盖，*深入研究 Linux 中的 C 语言*。如果您使用的是 CentOS 或 Fedora，这些手册很可能已经安装。否则，请查看我提到的*第三章*中的食谱，*深入研究 Linux 中的 C 语言*。

查看以下链接以查看代码演示视频：[`bit.ly/3u4OuWz`](https://bit.ly/3u4OuWz)

# 阅读 inode 信息并学习文件系统

理解 inode 是深入了解 Linux 文件系统的关键。在 Linux 或 Unix 系统中，文件名并不是实际的文件，它只是指向 inode 的指针。inode 包含有关实际数据存储位置的信息，以及有关文件的大量元数据，例如文件模式、最后修改日期和所有者。

在这个食谱中，我们将对**文件系统**有一个一般的了解，以及 inode 如何适应其中。我们还将查看 inode 信息，并学习一些相关命令。我们还将编写一个小的 C 程序，从文件名中读取 inode 信息。

## 准备工作

在这个食谱中，我们将使用命令和 C 程序来探索 inode 的概念。您需要的一切都在本章的*技术要求*部分中有所涵盖。

## 操作方法…

在这个配方中，我们将首先探索系统上已经存在的命令，以查看 inode 信息。然后，我们将创建一个小的 C 程序来打印 inode 信息：

1.  我们将首先创建一个小的文本文件，我们将在整个配方中使用它：

```
$> echo "This is just a small file we'll use" \
> > testfile1
$> cat testfile1 
This is just a small file we'll use
```

1.  现在，让我们查看此文件的*inode 编号*，以及其大小、块计数和其他信息。每个系统和每个文件的 inode 编号都是不同的：

```
$> stat testfile1 
  File: testfile1
  Size: 36              Blocks: 8          IO Block: 262144 regular file
Device: 35h/53d Inode: 19374124    Links: 1
Access: (0644/-rw-r--r--)  Uid: ( 1000/    jake)   Gid: ( 1000/    jake)
Access: 2020-10-16 22:19:02.770945984 +0200
Modify: 2020-10-16 22:19:02.774945969 +0200
Change: 2020-10-16 22:19:02.774945969 +0200
 Birth: -
```

1.  大小以字节为单位，为 36 字节。由于文本中未使用特殊字符，因此这与文件包含的字符数相同。我们可以使用`wc`来计算字符数：

```
$> wc -c testfile1 
36 testfile1
```

1.  现在，让我们构建一个小程序，提取其中一些信息；inode 编号、文件大小和`my-stat-v1.c`的链接数。我们将用于提取信息的系统调用函数与命令行工具`stat`具有相同的名称。代码中突出显示了系统调用函数：

```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(int argc, char *argv[])
{
   struct stat filestat;
   if ( argc != 2 )
   {
      fprintf(stderr, "Usage: %s <file>\n", 
         argv[0]);
      return 1;
   }
   if ( stat(argv[1], &filestat) == -1 )
   {
      fprintf(stderr, "Can't read file %s: %s\n", 
         argv[1], strerror(errno));
      return errno;
   }
   printf("Inode: %lu\n", filestat.st_ino);
   printf("Size: %zd\n", filestat.st_size);
   printf("Links: %lu\n", filestat.st_nlink);
   return 0;
}
```

1.  现在使用 Make 和通用的`Makefile`编译此程序：

```
$> make my-stat-v1
gcc -Wall -Wextra -pedantic -std=c99    my-stat-v1.c   -o my-stat-v1
```

1.  让我们在`testfile1`上尝试这个程序。比较 inode 编号、大小和链接数。这些数字应该与我们使用`stat`程序时相同：

```
$> ./my-stat-v1 testfile1 
Inode: 19374124
Size: 36
Links: 1
```

1.  如果我们不输入参数，将会得到一个使用消息：

```
$> ./my-stat-v1
Usage: ./my-stat-v1 <file>
```

1.  如果我们尝试对一个不存在的文件进行操作，将会得到一个错误消息：

```
$> ./my-stat-v1 hello123
Can't read file hello123: No such file or directory
```

## 工作原理…

文件的文件名并不是数据或文件。文件名只是指向 inode 的链接。而该 inode 又包含有关实际数据存储在文件系统上的位置的信息。正如我们将在下一篇文章中看到的，一个 inode 可以有多个名称或*链接*。有时文件名也被称为链接。下图说明了指向 inode 的文件名和 inode 包含有关**数据块**存储位置的信息的概念：

![图 5.1 – Inodes 和文件名](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sys-prog-tech/img/Figure_5.1_B13043.jpg)

图 5.1 – Inodes 和文件名

一个 inode 还包含`stat`命令。

在第 4 步中，我们创建了一个小的 C 程序，使用与命令相同名称的系统调用函数`stat()`读取此元数据。`stat()`系统调用提取的数据比我们在此处打印的要多得多。我们将在本章中打印更多此类信息。所有这些信息都存储在一个名为`stat`的结构体中。我们在`man 2 stat`手册页中找到了关于此结构体的所有所需信息。在该手册页中，我们还看到了变量的数据类型（`ino_t`、`off_t`和`nlink_t`）。然后，在`man sys_types.h`中，我们在**另外**下找到了这些类型是什么类型。

我们在这里使用的字段是`st_ino`表示 inode 编号，`st_size`表示文件大小，`st_nlink`表示文件的链接数。

在第 6 步中，我们看到我们使用 C 程序提取的信息与`stat`命令的信息相同。

我们还在程序中实现了错误处理。`stat()`函数包装在一个`if`语句中，检查其返回值是否为-1。如果发生错误，我们将使用`stderr`打印出带有文件名和`errno`的错误消息。程序还将`errno`变量返回给 shell。我们在*第四章**中学习了有关错误处理和`errno`的所有内容，处理程序中的错误*。

# 创建软链接和硬链接

在上一篇文章中，我们提到了链接的主题。在这篇文章中，我们将更多地了解链接以及它们对 inode 的影响。我们还将调查**软链接**和**硬链接**之间的区别。简而言之，硬链接是一个文件名，软链接就像是一个文件名的快捷方式。

此外，我们将编写两个程序，一个创建硬链接，一个创建软链接。然后，我们将使用前一篇文章中创建的程序来检查链接计数。

## 准备工作

除了本章开头列出的要求，您还需要我们在上一个示例中创建的程序`my-stat-v1.c`。您还需要我们在上一个示例中创建的测试文件，名为`testfile1`。如果您还没有创建这些文件，也可以从 GitHub 上下载它们[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch5`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch5)。

您还需要使用 Make 编译`my-stat-v1.c`程序，以便能够执行它，如果您还没有这样做的话。您可以使用`make my-stat-v1`来编译它。

## 如何做…

我们将创建软链接和硬链接，使用内置命令和编写简单的 C 程序来完成：

1.  我们将首先创建一个新的硬链接到我们的测试文件`testfile1`。我们将新的硬链接命名为`my-file`：

```
$> ln testfile1 my-file
```

1.  现在让我们调查这个新文件名。请注意链接已增加到`2`，但其余部分与`testfile1`相同：

```
$> cat my-file 
This is just a small file we'll use
$> ls -l my-file 
-rw-r--r-- 3 jake jake 36 okt 16 22:19 my-file
$> ./my-stat-v1 my-file 
Inode: 19374124
Size: 36
Links: 2
```

1.  现在将这些数字与`testfile1`文件进行比较。它们应该都是相同的：

```
$> ls -l testfile1 
-rw-r--r-- 3 jake jake 36 okt 16 22:19 testfile1
$> ./my-stat-v1 testfile1 
Inode: 19374124
Size: 36
Links: 2
```

1.  让我们创建另一个名为`another-name`的硬链接。我们使用名称`my-file`作为目标创建此链接：

```
$> ln my-file another-name
```

1.  我们也将调查这个文件：

```
$> ls -l another-name 
-rw-r--r-- 2 jake jake 36 okt 16 22:19 another-name
$> ./my-stat-v1 another-name 
Inode: 19374124
Size: 36
Links: 3
```

1.  现在让我们删除`testfile1`文件名：

```
$> rm testfile1
```

1.  现在我们已经删除了我们创建的第一个文件名，我们将调查另外两个名称：

```
$> cat my-file 
This is just a small file we'll use
$> ls -l my-file 
-rw-r--r-- 2 jake jake 36 okt 16 22:19 my-file
$> ./my-stat-v1 my-file 
Inode: 19374124
Size: 36
Links: 2
$> cat another-name 
This is just a small file we'll use
$> ls -l another-name 
-rw-r--r-- 2 jake jake 36 okt 16 22:19 another-name
$> ./my-stat-v1 another-name 
Inode: 19374124
Size: 36
Links: 2
```

1.  是时候创建一个软链接了。我们创建一个名为`my-soft-link`的软链接到名称`another-name`：

```
$> ln -s another-name my-soft-link
```

1.  软链接是一种特殊的文件类型，可以使用`ls`命令查看。请注意，我们在这里得到了一个新的时间戳。还要注意，它是一个特殊文件，可以通过文件模式字段中的第一个字母`l`来看到：

```
$> ls -l my-soft-link 
lrwxrwxrwx 1 jake jake 12 okt 17 01:49 my-soft-link -> another-name
```

1.  现在让我们检查`another-name`的链接计数。请注意，软链接的计数器没有增加：

```
$> ./my-stat-v1 another-name 
Inode: 19374124
Size: 36
Links: 2
```

1.  是时候编写我们自己的程序来创建硬链接了。存在一个易于使用的`link()`，我们将使用它。将以下代码写入文件并保存为`new-name.c`。代码中突出显示了`link()`系统调用：

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s [target] " 
            "[new-name]\n", argv[0]);
        return 1;
    }
    if (link(argv[1], argv[2]) == -1)
    {
        perror("Can't create link");
        return 1;
    }
    return 0;
}
```

1.  编译程序：

```
$> make new-name
gcc -Wall -Wextra -pedantic -std=c99    new-name.c   -o new-name
```

1.  为我们之前的`my-file`文件创建一个新名称。将新文件命名为`third-name`。我们还尝试生成一些错误，以查看程序是否打印了正确的错误消息。请注意，`third-name`的 inode 信息与`my-file`的相同：

```
$> ./new-name 
Usage: ./new-name [target][new-name]
$> ./new-name my-file third-name
$> ./my-stat-v1 third-name
Inode: 19374124
Size: 36
Links: 3
$> ./new-name my-file /home/carl/hello
Can't create link: Permission denied
$> ./new-name my-file /mnt/localnas_disk2/
Can't create link: File exists
$> ./new-name my-file /mnt/localnas_disk2/third-name
Can't create link: Invalid cross-device link
```

1.  现在让我们创建一个创建软链接的程序。这也有一个易于使用的系统调用，称为`symlink()`，用于`new-symlink.c`。代码中突出显示了`symlink()`系统调用。注意所有这些系统调用函数有多么相似：

```
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s [target] " 
            "[link]\n", argv[0]);
        return 1;
    }
    if (symlink(argv[1], argv[2]) == -1)
    {
        perror("Can't create link");
        return 1;
    }
    return 0;
}
```

1.  编译它：

```
$> make new-symlink
gcc -Wall -Wextra -pedantic -std=c99    new-symlink.c   -o new-symlink
```

1.  让我们试一试，创建一个新的软链接，名为`new-soft-link`，指向`third-name`。此外，让我们尝试生成一些错误，以便我们可以验证错误处理是否正常工作：

```
$> ./new-symlink third-name new-soft-link
$> ls -l new-soft-link 
lrwxrwxrwx 1 jake jake 10 okt 18 00:31 new-soft-link -> third-name
$> ./new-symlink third-name new-soft-link
Can't create link: File exists
$> ./new-symlink third-name /etc/new-soft-link
Can't create link: Permission denied
```

## 它是如何工作的…

这里发生了很多事情，所以让我们从头开始。

在步骤 1 到 7 中，我们创建了两个新的硬链接到`testfile1`文件。但正如我们注意到的，硬链接没有什么特别之处；它只是 inode 的另一个名称。所有文件名都是硬链接。文件名只是 inode 的一个链接。当我们删除`testfile1`文件名时，我们看到了这一点。剩下的两个名称链接到相同的 inode，并且包含相同的文本。第一个文件名或链接没有什么特别之处。无法告诉哪个硬链接是首先创建的。它们是相等的；它们甚至共享相同的日期，尽管其他链接是在稍后的时间创建的。日期是为了 inode，而不是文件名。

当我们创建和删除硬链接时，我们看到链接计数增加和减少。这是 inode 保持计算它有多少链接或名称的计数。

直到最后一个名称被删除，即链接计数达到零时，inode 才会被删除。

在*步骤 8 到 10*中，我们看到软链接，另一方面，是一种特殊的文件类型。软链接不计入 inode 的链接计数。文件在`ls -l`输出的开头用`l`表示。我们还可以在`ls -l`输出中看到软链接指向的文件。把软链接想象成一个快捷方式。

在*步骤 11 到 13*中，我们编写了一个创建硬链接（现有文件的新名称）的 C 程序。在这里，我们了解到创建新名称的系统调用称为`link()`，并且接受两个参数，目标和新名称。

在*步骤 13*中，我们见证了硬链接的一个有趣特性。它们不能跨设备。当我们考虑这一点时，这是有道理的。文件名不能保留在与 inode 分开的设备上。如果设备被移除，可能就没有更多的名称指向 inode，使其无法访问。

在剩下的步骤中，我们编写了一个 C 程序，用于创建指向现有文件的软链接。这个系统调用类似于`link()`，但是被称为`symlink()`。

## 还有更多...

请查看我们在本食谱中涵盖的系统调用的手册页面；它们包含了硬链接和软链接的一些很好的解释。手册页面是`man 2 link`和`man 2 symlink`。

# 创建文件和更新时间戳

现在我们了解了文件系统、inode 和硬链接，我们将学习如何通过在 C 中编写我们自己的`touch`版本来创建文件。我们已经开始在*第四章**，处理程序中的错误*中编写`touch`的一个版本，那里我们学习了错误处理。我们将继续使用该程序的最新版本，我们将其命名为`simple-touch-v7.c`。真正的`touch`版本会在文件存在时更新文件的修改和访问时间戳。在这个食谱中，我们将在我们的新版本中添加这个功能。

## 准备工作

您在本章的*技术要求*部分中列出了此食谱所需的一切。虽然我们将添加`simple-touch`的最新版本，但我们将在本食谱中编写整个代码。但为了完全理解程序，最好先阅读*第四章**，处理程序中的错误*。

## 如何做...

在这个`simple-touch`的第八个版本中，我们将添加更新文件的访问和修改日期的功能：

1.  在文件中写入以下代码，并将其保存为`simple-touch-v8.c`。在这里，我们将使用`utime()`系统调用来更新文件的访问和修改时间戳。代码中突出显示了与上一个版本的更改（除了添加的注释）。还要注意`creat()`系统调用如何移入了一个`if`语句。只有在文件不存在时才会调用`creat()`系统调用：

```
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <utime.h>
#define MAX_LENGTH 100
int main(int argc, char *argv[])
{
   char filename[MAX_LENGTH] = { 0 };
   /* Check number of arguments */
   if (argc != 2)
   {
      fprintf(stderr, "You must supply a filename "
         "as an argument\n");
      return 1;
   }
   strncat(filename, argv[1], sizeof(filename)-1);
   /* Update the access and modification time */
   if ( utime(filename, NULL) == -1 )
   {
      /* If the file doesn't exist, create it */
      if (errno == ENOENT)
      {
         if ( creat(filename, 00644) == -1 )
         {
            perror("Can't create file");
            return errno;
         }
      }
      /* If we can't update the timestamp,
         something is wrong */
      else
      {
         perror("Can't update timestamp");
         return errno;
      }
   }
   return 0;
}
```

1.  使用 Make 编译程序：

```
$> make simple-touch-v8
gcc -Wall -Wextra -pedantic -std=c99    simple-touch-v8.c   -o simple-touch-v8
```

1.  让我们尝试一下，看看它是如何工作的。我们将在上一个食谱中创建的文件名上尝试，并看看每个文件名如何获得相同的时间戳，因为它们都指向相同的 inode：

```
$> ./simple-touch-v8 a-new-file
$> ls -l a-new-file 
-rw-r--r-- 1 jake jake 0 okt 18 19:57 a-new-file
$> ls -l my-file 
-rw-r--r-- 3 jake jake 36 okt 16 22:19 my-file
$> ls -l third-name 
-rw-r--r-- 3 jake jake 36 okt 16 22:19 third-name
$> ./simple-touch-v8 third-name
$> ls -l my-file 
-rw-r--r-- 3 jake jake 36 okt 18 19:58 my-file
$> ls -l third-name 
-rw-r--r-- 3 jake jake 36 okt 18 19:58 third-name
$> ./simple-touch-v8 /etc/passwd
Can't change filename: Permission denied
$> ./simple-touch-v8 /etc/hello123
Can't create file: Permission denied
```

## 它是如何工作的...

在这个食谱中，我们添加了更新文件或 inode 的时间戳的功能。

要更新访问和修改时间，我们使用`utime()`系统调用。`utime()`系统调用接受两个参数，一个文件名和一个时间戳。但是如果我们将`NULL`作为第二个参数传递给函数，它将使用当前的时间和日期。

调用`utime()`的语句被包裹在一个`if`语句中，检查返回值是否为-1。如果是，那么出现了问题，`errno`被设置（参见*第四章**，处理程序中的错误*，对`errno`的深入解释）。然后我们使用`errno`来检查是否是*文件未找到*错误（`ENOTENT`）。如果文件不存在，我们使用`creat()`系统调用来创建它。对`creat()`的调用也被包裹在一个`if`语句中。如果在创建文件时出现问题，程序将打印错误消息并返回`errno`值。如果程序成功创建了文件，它将继续执行`return 0`。

如果`utime()`的`errno`值不是`ENOENT`，它将继续到`else`语句，打印错误消息，并返回`errno`。

当我们尝试运行程序时，我们注意到当我们更新其中一个文件时，`my-file`和`third-name`都会获得更新的时间戳。这是因为这些文件名只是指向相同 inode 的链接。时间戳是 inode 中的元数据。

## 还有更多...

在`man 2 creat`和`man 2 utime`中有很多有用的信息。如果你有兴趣了解 Linux 中的时间和日期，我建议你阅读`man 2 time`，`man 3 asctime`和`man time.h`。

# 删除文件

在这个食谱中，我们将学习如何使用`unlink()`函数。这个食谱将增强你对链接的理解，并闭合循环。这将提高你对 Linux 及其文件系统的整体知识。知道如何使用系统调用删除文件将使你能够直接从程序中删除文件。

在这里，我们将编写我们自己的版本的`rm`，我们将其称为`remove`。在这个食谱之后，我们知道如何创建和删除文件以及如何创建链接。这些是一些最常见的文件系统操作。

## 准备就绪

在这个食谱中，我们将使用我们在*读取 inode 信息和学习文件系统*食谱中编写的`my-stat-v1`程序。我们还将继续对我们在之前的食谱中创建的文件名进行实验，`my-file`，`another-name`和`third-name`。除此之外，你还需要本章列出的*技术要求*，即 GCC 编译器，Make 工具和通用 Makefile。

## 如何做...

跟着这里写一个简单版本的`rm`：

1.  将以下代码写入一个文件并保存为`remove.c`。这个程序使用`unlink()`系统调用来删除一个文件。代码中突出显示了系统调用：

```
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s [path]\n",
            argv[0]);
        return 1;
    }
    if ( unlink(argv[1]) == -1 )
    {
        perror("Can't remove file");
        return errno;
    }
    return 0;
}
```

1.  使用**Make**工具编译它：

```
$> make remove
gcc -Wall -Wextra -pedantic -std=c99    remove.c   -o remove
```

1.  让我们试一试：

```
$> ./my-stat-v1 my-file 
Inode: 19374124
Size: 36
Links: 3
$> ./remove another-name 
$> ./my-stat-v1 my-file 
Inode: 19374124
Size: 36
Links: 2
```

## 它是如何工作的...

用于删除文件的系统调用称为`unlink()`。这个名字来自于当我们删除一个文件名时，我们只是删除了指向该 inode 的硬链接；因此我们**unlink**了一个文件名。如果它恰好是指向 inode 的最后一个文件名，那么该 inode 也将被删除。

`unlink()`系统调用只接受一个参数：我们要删除的文件名。

# 获取访问权限和所有权

在这个食谱中，我们将编写一个程序，使用我们在本章中之前看到的`stat()`系统调用来读取文件的访问权限和所有权。我们将继续构建在本章第一个食谱中构建的`my-stat-v1`程序的基础上。在这里，我们将添加显示所有权和访问权限的功能。知道如何以编程方式获取所有者和访问权限对于处理文件和目录至关重要。它将使你能够检查用户是否具有适当的权限，并在他们没有权限时打印错误消息。

我们还将学习在 Linux 中如何解释访问权限以及如何在数字表示和字母表示之间进行转换。了解 Linux 中的访问权限对于成为 Linux 系统程序员至关重要。整个系统上的每个文件和目录都有访问权限以及分配给它们的所有者和组。无论是日志文件、系统文件还是用户拥有的文本文件，都有访问权限。

## 准备工作

对于这个示例，您只需要本章*技术要求*部分中列出的内容。

## 如何做…

我们将在这个示例中编写`my-stat-v1`的新版本。我们将在这里编写整个程序，因此您不需要之前的版本：

1.  在文件中写入以下代码并将其保存为`my-stat-v2.c`。在这个版本中，我们将获取有关文件所有者和组以及文件模式的信息。要翻译`getpwuid()`。要获取`getgrgid()`的组名。更改在代码中突出显示：

```
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
int main(int argc, char *argv[])
{
    struct stat filestat;
    struct passwd *userinfo;
    struct group *groupinfo;
    if ( argc != 2 )
    {
        fprintf(stderr, "Usage: %s <file>\n",
            argv[0]);
        return 1;
    }
    if ( stat(argv[1], &filestat) == -1 )
    {
        fprintf(stderr, "Can't read file %s: %s\n", 
            argv[1], strerror(errno));
        return errno;
    }
    if ( (userinfo = getpwuid(filestat.st_uid)) ==
        NULL )
    {
        perror("Can't get username");
        return errno;
    }
    if ( (groupinfo = getgrgid(filestat.st_gid)) ==
        NULL )
    {
        perror("Can't get groupname");
        return errno;
    }
    printf("Inode: %lu\n", filestat.st_ino);
    printf("Size: %zd\n", filestat.st_size);
    printf("Links: %lu\n", filestat.st_nlink);
printf("Owner: %d (%s)\n", filestat.st_uid, 
        userinfo->pw_name);
printf("Group: %d (%s)\n", filestat.st_gid, 
        groupinfo->gr_name);
    printf("File mode: %o\n", filestat.st_mode);
    return 0;
}
```

1.  编译程序：

```
$> make my-stat-v2
gcc -Wall -Wextra -pedantic -std=c99    my-stat-v2.c   -o my-stat-v2
```

1.  在一些不同的文件上尝试该程序：

```
$> ./my-stat-v2 third-name 
Inode: 19374124
Size: 36
Links: 2
Owner: 1000 (jake)
Group: 1000 (jake)
File mode: 100644
$> ./my-stat-v2 /etc/passwd
Inode: 4721815
Size: 2620
Links: 1
Owner: 0 (root)
Group: 0 (root)
File mode: 100644
$> ./my-stat-v2 /bin/ls
Inode: 3540019
Size: 138856
Links: 1
Owner: 0 (root)
Group: 0 (root)
File mode: 100755
```

## 工作原理…

在这个`my-stat`版本中，我们添加了检索文件访问模式或实际上是**文件模式**的功能。文件的完整文件模式由六个八进制数字组成。前两个（左侧）是文件类型。在这种情况下，它是一个常规文件（10 等于常规文件）。第四个八进制数字是**设置用户 ID 位**、**设置组 ID 位**和**粘性位**。最后三个八进制数字是**访问模式**。

在`ls -l`的输出中，所有这些位都代表为字母。但是当我们编写程序时，我们必须将其设置和读取为数字。在继续之前，让我们检查文件模式的字母版本，以便真正理解它：

！图 5.2 - 文件访问模式



图 5.2 - 文件访问模式

设置用户 ID 位是一个允许进程以二进制文件的所有者身份运行的位，即使它以不同的用户身份执行。设置用户 ID 位可能是危险的，*不*是我们应该在程序上设置的东西。使用设置用户 ID 位的一个程序是`passwd`程序。`passwd`程序必须在用户更改密码时更新`/etc/passwd`和`/etc/shadow`文件，即使这些文件是由 root 拥有的。在正常情况下，我们甚至不能以常规用户的身份读取`/etc/shadow`文件，但是通过在`passwd`程序上设置设置用户 ID 位，它甚至可以写入它。如果设置了设置用户 ID 位，则在用户的访问模式的第三个位置上用`s`表示。

设置组 ID 具有类似的效果。当程序被执行并且设置了组 ID 位时，它将作为该组执行。当设置了组 ID 时，它在组的访问模式的第三个位置上用`s`表示。

粘性位在历史上用于将程序*粘*到交换空间，以加快加载时间。现在，它的用途完全不同。现在，名称以及含义都已更改为*受限删除标志*。当目录设置了粘性位时，只有文件的所有者、目录所有者或 root 用户可以删除文件，即使目录可被任何人写入。例如，`/tmp`目录通常设置了粘性位。粘性位在最后一组的最后一个位置上用`t`表示。

### 文件访问模式

当我们在文件上运行`ls -l`时，我们总是看到两个名称。第一个名称是用户（所有者），第二个名称是拥有文件的组。例如：

```
$> ls -l Makefile 
```

```
-rw-r--r-- 1 jake devops 134 okt 27 23:39 Makefile
```

在这种情况下，`jake`是用户（所有者），`devops`是组。

文件访问模式比我们刚刚讨论的特殊标志更容易理解。看一下*图 5.2*。前三个字母是用户的访问模式（文件的所有者）。这个特定的示例有`rw-`，这意味着用户可以读取和写入文件，但不能执行它。如果用户能够执行它，那将在最后一个位置上用`x`表示。

中间的三个字母是组访问模式（拥有文件的组）。在这种情况下，由于组缺少写入和执行的`w`和`x`，组只能读取文件。

最后的三个字母是所有其他人（不是所有者，也不在所有者组中）。在这种情况下，其他人只能读取文件。

完整的权限集将是`rwxrwxrwx`。

### 在字母和数字之间转换访问模式

**八进制数**表示文件访问模式。在我们习惯之前，从字母转换为八进制的最简单方法是使用纸和笔。我们在每个设置了访问位的组中将所有数字相加。如果没有设置（破折号），那么我们就不添加那个数字。当我们完成每个组的添加时，我们就得到了访问模式：

```
rw- r-- r—
```

```
421 421 421
```

```
 6   4   4
```

因此，前面的八进制访问模式是 644。让我们再举一个例子：

```
rwx rwx r-x
```

```
421 421 421
```

```
 7   7   5
```

前面的访问模式结果是 775。让我们再举一个例子：

```
rw- --- ---
```

```
421 421 421
```

```
 6   0   0
```

这个访问模式是 600。

也可以使用纸和笔来做相反的事情。假设我们有访问模式 750，我们想把它转换成字母：

```
 7   5   0
```

```
421 401 000
```

```
rwx r-x ---
```

因此，750 变成了`rwxr-x---`。

当你做了一段时间后，你会学会最常用的访问模式，不再需要纸和笔。

### 八进制文件模式

与文件访问模式一样，这里也适用相同的原则。记住，用户 ID 由用户的执行位置上的`s`表示，组 ID 由组的执行位上的`s`表示。`t`字符表示最后一个执行位位置（“其他”）的粘性位。如果我们把它写在一行上，就会得到这样：

```
s s t
```

```
4 2 1
```

因此，如果只设置了用户 ID 位，我们得到 4。如果同时设置了用户 ID 和组 ID，我们得到*4+2=6*。如果只设置了组 ID 位，我们得到 2。如果只设置了粘性位，我们得到 1，依此类推。如果所有位都设置了，我们得到*7（4+2+1）*。

这些文件模式由文件访问模式之前的数字表示。例如，八进制文件模式`4755`设置了用户 ID 位（4）。

当我们在 Linux 下编程时，我们甚至可能会遇到另外两个数字，就像我们从`my-stat-v2`程序的输出中看到的那样。在那里，我们有这样的：

```
File mode: 100755
```

前两个数字，在这个例子中是`10`，是文件类型。这两个数字的确切含义是我们需要在`man 7 inode`手册页中查找的。那里有一个很好的表告诉我们它的含义。我在这里列出了一个简化的列表，只显示我们感兴趣的前两个数字以及它代表的文件类型：

```
14   socket
```

```
12   symbolic link
```

```
10   regular file
```

```
06   block device
```

```
04   directory
```

```
02   character device
```

```
01   FIFO
```

这意味着我们的示例文件是一个普通文件（10）。

如果我们把刚刚学到的所有东西加起来，并将前面示例输出的`my-stat-v2`中的文件模式*100755*转换成数字，我们得到这样：

```
10  = a regular file
```

```
0   = no set-user-ID, set-group-ID or sticky bit is set
```

```
755 = the user can read, write, and execute it. The group can read and execute it, and all others can also read and execute it.
```

文件类型也由第一个位置的字母表示（见*图 5.2*）。这些字母如下：

```
s   socket
```

```
l   symbolic link
```

```
-   regular file
```

```
b   block device
```

```
d   directory
```

```
c   character device
```

```
p   FIFO
```

# 设置访问权限和所有权

在上一个配方中，我们学习了如何读取`chmod`命令和`chmod()`系统调用。我们还将学习如何改变文件的所有者和组，使用`chown`命令和`chown()`系统调用。

知道如何正确设置访问权限将有助于保护您的系统和文件安全。

## 准备工作

对于这个配方，你只需要本章*技术要求*部分列出的内容。阅读上一个配方以理解 Linux 中的权限也是一个好主意。你还需要上一个配方中的`my-stat-v2`程序。

## 如何做…

这些步骤将教会我们如何更改文件和目录的访问权限和所有权。

### 访问权限

我们将首先使用`chmod`命令设置文件的访问权限。然后，我们将编写`chmod`命令的简单 C 版本，使用`chmod()`系统调用：

1.  让我们首先使用`chmod`命令从我们的`my-stat-v2`程序中删除执行权限。以下命令中的`-x`表示*删除执行*：

```
$> chmod -x my-stat-v2
```

1.  现在让我们尝试执行程序。这次应该因为权限被拒绝而失败：

```
$> ./my-stat-v2
bash: ./my-stat-v2: Permission denied
```

1.  现在我们再次改回来，但这次我们使用八进制数字设置*绝对*权限。可执行文件的适当权限是 755，对应`rwxr-xr-x`。这意味着用户有完全权限，组可以读取和执行文件。其他所有人也一样；他们可以读取和执行它：

```
$> chmod 755 my-stat-v2
```

1.  在这个命令之后，我们可以再次执行程序：

```
./my-stat-v2 
Usage: ./my-stat-v2 <file>
```

1.  现在是时候编写`chmod`命令的简单版本，使用`chmod()`系统调用。将以下代码写入文件并保存为`my-chmod.c`。`chmod()`系统调用接受两个参数，文件或目录的路径和以八进制数表示的文件权限。在进行`chmod()`系统调用之前，我们进行一些检查，以确保权限看起来合理（一个三位或四位数的八进制数）。检查后，我们使用`strtol()`将数字转换为八进制数。`strtol()`的第三个参数是基数，这里是`8`：

```
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
void printUsage(FILE *stream, char progname[]);
int main(int argc, char *argv[])
{
   long int accessmode; /*To hold the access mode*/
   /* Check that the user supplied two arguments */
   if (argc != 3)
   {
      printUsage(stderr, argv[0]);
      return 1;
   }
   /* Simple check for octal numbers and 
      correct length */
   if( strspn(argv[1], "01234567\n") 
         != strlen(argv[1]) 
         || ( strlen(argv[1]) != 3 && 
              strlen(argv[1]) != 4 ) )
   {
      printUsage(stderr, argv[0]);
      return 1;
   }
   /* Convert to octal and set the permissions */
   accessmode = strtol(argv[1], NULL, 8);
   if (chmod(argv[2], accessmode) == -1)
   {
      perror("Can't change permissions");
   }
   return 0;
}
void printUsage(FILE *stream, char progname[])
{
    fprintf(stream, "Usage: %s <numerical "
        "permissions> <path>\n", progname);
}
```

1.  现在编译程序：

```
$> make my-chmod
gcc -Wall -Wextra -pedantic -std=c99    my-chmod.c   -o my-chmod
```

1.  使用不同的权限测试程序。不要忘记使用`ls -l`检查结果：

```
$> ./my-chmod 
Usage: ./my-chmod <numerical permissions> <path>
$> ./my-chmod 700 my-stat-v2
$> ls -l my-stat-v2
-rwx------ 1 jake jake 17072 Nov  1 07:29 my-stat-v2
$> ./my-chmod 750 my-stat-v2
$> ls -l my-stat-v2
-rwxr-x--- 1 jake jake 17072 Nov  1 07:29 my-stat-v2
```

1.  让我们也尝试设置设置用户 ID 位。这里的设置用户 ID 位（以及设置组 ID 位和粘性位）是访问模式前面的第四位数字。这里的`4`设置了设置用户 ID 位。请注意用户字段中的`s`（在下面的代码中突出显示）：

```
$> chmod 4755 my-stat-v2
$> ls -l my-stat-v2
-rwsr-xr-x 1 jake jake 17072 Nov  1 07:29 my-stat-v2
```

1.  让我们尝试设置所有位（设置用户 ID、设置组 ID、粘性位和所有权限）：

```
$> chmod 7777 my-stat-v2
$> ls -l my-stat-v2
-rwsrwsrwt 1 jake jake 17072 Nov  1 07:29 my-stat-v2
```

1.  最后，将其改回更合理的东西：

```
$> chmod 755 my-stat-v2
$> ls -l my-stat-v2
-rwxr-xr-x 1 jake jake 17072 Nov  1 07:29 my-stat-v2
```

### 所有权

但我们也需要知道如何改变`chown`命令或`chown()`系统调用：

1.  要改变文件的所有者，我们必须是 root。普通用户不能放弃对他们的文件的所有权。同样，他们也不能声明对别人的文件的所有权。让我们尝试使用`chown`命令将`my-stat-v2`的所有者更改为 root：

```
$> sudo chown root my-stat-v2
$> ls -l my-stat-v2
-rwxr-xr-x 1 root jake 17072 Nov  1 07:29 my-stat-v2
```

1.  如果我们想要改变所有者和组，我们使用冒号分隔用户和组。第一个字段是所有者，第二个字段是组：

```
$> sudo chown root:root my-stat-v2
$> ls -l my-stat-v2
-rwxr-xr-x 1 root root 17072 Nov  1 07:29 my-stat-v2
```

1.  现在轮到我们编写一个简化版本的`chown`，使用`chown()`系统调用。`chown()`系统调用只接受用户 ID 作为数值。为了能够使用名称，我们必须首先使用`getpwnam()`查找用户名。这将在`passwd`结构中的`pw_uid`字段中给我们数值。对于组也是一样。我们必须使用`getgrnam()`系统调用使用其名称获取数值组 ID。现在我们知道了所有的系统调用，让我们写程序。将其命名为`my-chown.c`。这个程序有点长，所以我把它分成了几个步骤。请记住，所有步骤都应该放在一个文件（`my-chown.c`）中。如果愿意，您也可以从[`github.com/PacktPublishing/Linux-System-Programming-Techniques/blob/master/ch5/my-chown.c`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/blob/master/ch5/my-chown.c)下载整个代码。让我们从所有的头文件、变量和参数检查开始：

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <errno.h>
int main(int argc, char *argv[])
{
   struct passwd *user; /* struct for getpwnam */
   struct group *grp; /* struct for getgrnam */
   char *username = { 0 }; /* extracted username */
   char *groupname = { 0 }; /*extracted groupname*/
   unsigned int uid, gid; /* extracted UID/GID */
   /* Check that the user supplied two arguments 
      (filename and user or user:group) */
   if (argc != 3)
   {
      fprintf(stderr, "Usage: %s [user][:group]" 
         " [path]\n", argv[0]);
      return 1;
   }
```

1.  由于我们将用户名和组写为`username:group`在参数中，我们需要提取用户名部分和组部分。我们使用一个名为`strtok()`的字符串函数来做到这一点。在第一次调用`strtok()`时，我们只提供第一个参数（字符串）。之后，我们得到`user`结构和`grp`结构。我们还检查用户和组是否存在：

```
 /* Extract username and groupname */
   username = strtok(argv[1], ":");
   groupname = strtok(NULL, ":");

   if ( (user = getpwnam(username)) == NULL )
   {
      fprintf(stderr, "Invalid username\n");
      return 1;
   }
   uid = user->pw_uid; /* get the UID */
   if (groupname != NULL) /* if we typed a group */
   {
      if ( (grp = getgrnam(groupname)) == NULL )
      {
         fprintf(stderr, "Invalid groupname\n");
         return 1;
      }
      gid = grp->gr_gid; /* get the GID */
   }
   else
   {
      /* if no group is specifed, -1 won't change 
         it (man 2 chown) */
      gid = -1;
   }
```

1.  最后，我们使用`chown()`系统调用来更新文件的用户和组：

```
   /* update user/group (argv[2] is the filename)*/
   if ( chown(argv[2], uid, gid) == -1 )
   {
      perror("Can't change owner/group");
      return 1;
   }
   return 0;
}
```

1.  让我们编译程序，这样我们就可以尝试它：

```
$> make my-chown
gcc -Wall -Wextra -pedantic -std=c99    my-chown.c   -o my-chown
```

1.  现在我们在一个文件上测试程序。请记住，我们需要以 root 身份更改文件的所有者和组：

```
$> ls -l my-stat-v2 
-rwxr-xr-x 1 root root 17072 nov  7 19:59 my-stat-v2
$> sudo ./my-chown jake my-stat-v2 
$> ls -l my-stat-v2 
-rwxr-xr-x 1 jake root 17072 nov  7 19:59 my-stat-v2
$> sudo ./my-chown carl:carl my-stat-v2 
$> ls -l my-stat-v2 
-rwxr-xr-x 1 carl carl 17072 nov  7 19:59 my-stat-v2
```

## 它是如何工作的...

系统上的每个文件和目录都有访问权限和一个所有者/组对。访问权限可以使用`chmod`命令或`chmod()`系统调用来更改。该名称是*更改模式位*的缩写。在上一个示例中，我们介绍了如何在更人类可读的文本格式和数字八进制格式之间转换访问权限。在这个示例中，我们编写了一个使用`chmod()`系统调用使用数字形式更改模式位的程序。

为了将数字形式转换为八进制数，我们使用`strtol()`和`8`作为第三个参数，这是数字系统的基数。基数 8 是八进制；基数 10 是我们在日常生活中使用的常规十进制系统；基数 16 是十六进制，依此类推。

我们编写了程序，以便用户可以选择他们想要设置的任何内容，无论是只有访问模式位（三位数）还是特殊位，如设置用户 ID、设置组 ID 和粘性位（四位数）。为了确定用户输入的数字位数，我们使用`strlen()`。

在下一个程序中，我们使用`chown()`来更新文件或目录的所有者和组。由于我们想要使用名称而不是数字 UID 和 GID 来更新用户和组，程序变得更加复杂。`chown()`系统调用只接受 UID 和 GID，而不是名称。这意味着我们需要在调用`chown()`之前查找 UID 和 GID。为了查找 UID 和 GID，我们使用`getpwnam()`和`getgrnam()`。这些函数中的每一个都给我们一个包含相应用户或组的所有可用信息的`struct`。从这些结构中，我们提取 UID 和 GID，然后在调用`chown()`时使用它们。

为了从命令行中分离用户名和组部分（冒号），我们使用`strtok()`函数。在对函数的第一次调用中，我们将字符串指定为第一个参数（在本例中为`argv[1]`），并指定分隔符（冒号）。在对`strtok()`的下一次调用中，我们将字符串设置为`NULL`，但仍然指定分隔符。第一次调用给我们用户名，第二次调用给我们组名。

之后，当我们调用`getpwnam()`和`getgrnam()`时，我们检查用户名和组名是否存在。如果用户名或组名不存在，函数将返回`NULL`。

## 还有更多...

有几个类似的函数可以使用`getpwnam()`和`getgrnam()`，具体取决于您拥有的信息和您拥有的信息。如果您有 UID，您可以使用`getpwuid()`。同样，如果您有 GID，您可以使用`getgrgid()`。如果您阅读`man 3 getpwnam`和`man 3 getgrnam`手册页面，将会有更多的信息和更多的函数。

# 使用文件描述符写入文件

在之前的章节中，我们已经看到了**文件描述符**的一些用法，例如 0、1 和 2（*stdin*、*stdout*和*stderr*）。但在这个示例中，我们将使用文件描述符从程序中写入文本到文件。

了解如何使用文件描述符来写入文件既可以让您更深入地了解系统，也可以让您做一些底层的事情。

## 准备工作

对于这个示例，您只需要在*技术要求*部分列出的内容。

## 如何做...

在这里，我们将编写一个小程序来向文件写入文本：

1.  在文件中写入以下代码，并将其保存为`fd-write.c`。该程序接受两个参数：一个字符串和一个文件名。要使用文件描述符写入文件，我们必须首先使用`open()`系统调用打开文件。`open()`系统调用返回一个文件描述符，这是一个整数。然后我们使用该文件描述符（整数）与`write()`系统调用。我们已经在*第三章**中看到了`write()`，在那一章中，我们使用`write()`将一个小文本写入标准输出。这一次，我们使用`write()`将文本写入文件。请注意，`open()`系统调用接受三个参数：文件的路径，文件应该以哪种模式打开（在这种情况下，如果文件不存在则创建文件，并以读写模式打开），以及`0644`）：

```
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
int main(int argc, char *argv[])
{
   int fd; /* for the file descriptor */
   if (argc != 3)
   {
      fprintf(stderr, "Usage: %s [path] [string]\n",
         argv[0]);
      return 1;
   }
   /* Open the file (argv[1]) and create it if it 
      doesn't exist and set it in read-write mode. 
      Set the access mode to 644 */
   if ( (fd = open(argv[1], O_CREAT|O_RDWR, 00644)) 
      == -1 )
   {
      perror("Can't open file for writing");
      return 1;
   }
   /* write content to file */
   if ( (write(fd, argv[2], strlen(argv[2]))) 
      == -1 )
   {
      perror("Can't write to file");
      return 1;
   }
   return 0;
}
```

1.  让我们编译这个程序：

```
$> make fd-write
gcc -Wall -Wextra -pedantic -std=c99    fd-write.c   -o fd-write
```

1.  让我们尝试向文件中写入一些文本。请记住，如果文件已经存在，内容将被覆盖！如果新文本比文件的旧内容小，那么只有开头会被覆盖。还要注意，如果文本不包含换行符，那么文件中的文本也不会包含换行符：

```
$> ./fd-write testfile1.txt "Hello! How are you doing?"
$> cat testfile1.txt 
Hello! How are you doing?$>*Enter*
$> ls -l testfile1.txt 
-rw-r--r-- 1 jake jake 2048 nov  8 16:34 testfile1.txt
$> ./fd-write testfile1.txt "A new text"
$> cat testfile1.txt 
A new text are you doing?$>
```

1.  我们甚至可以从另一个文件中输入内容，如果我们使用`xargs`，这是一个允许我们将程序的输出解析为另一个程序的命令行参数的程序。请注意，这一次，`testfile1`将在末尾有一个换行符。`xargs`的`-0`选项使其忽略换行符，而是使用空字符来表示参数的结尾：

```
$> head -n 3 /etc/passwd | xargs -0 \
> ./fd-write testfile1.txt 
$> cat testfile1.txt 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

## 工作原理…

`open()`系统调用返回一个文件描述符，我们将其保存在`fd`变量中。文件描述符只是一个整数，就像 0、1 和 3 是*stdin*、*stdout*和*stderr*一样。

我们给`open()`的第二个参数是使用*按位或*组合在一起的模式位的宏。在我们的情况下，我们同时使用`O_CREAT`和`O_RDWR`。第一个`O_CREAT`表示如果文件不存在，则创建文件。第二个`O_RDWR`表示文件应该同时用于读取和写入。

要将字符串写入文件，我们将文件描述符作为第一个参数传递给`write()`。作为第二个参数，我们给它`argv[2]`，其中包含我们要写入文件描述符的字符串。最后一个参数是我们要写入的内容的大小。在我们的情况下，我们使用`strlen`来获取`argv[2]`的大小，这是`string.h`中的一个函数，用于获取字符串的长度。

就像在以前的食谱中一样，我们检查所有系统调用是否返回`-1`。如果它们返回`-1`，则表示出现了问题，我们使用`perror()`打印错误消息，然后返回`1`。

## 还有更多…

当程序正常返回时，所有打开的文件描述符都会自动关闭。但是，如果我们想显式关闭文件描述符，我们可以使用`close()`系统调用，并将文件描述符作为其参数。在我们的情况下，我们可以在返回之前添加`close(fd)`。

手册页面中有关`open()`、`close()`和`write()`的很多有用信息。我建议您阅读它们以获取更深入的信息。您可以使用以下命令阅读它们：

+   `man 2 open`

+   `man 2 close`

+   `man 2 write`

# 使用文件描述符从文件中读取

在上一个食谱中，我们学会了如何使用文件描述符写入文件。在这个食谱中，我们将学习如何使用文件描述符从文件中读取。因此，我们将编写一个类似于`cat`的小程序。它接受一个参数——文件名，并将其内容打印到标准输出。

了解如何读取和使用文件描述符使您不仅可以读取文件，还可以读取通过文件描述符传输的各种数据。文件描述符是在 Unix 和 Linux 中读取和写入数据的通用方式。

## 准备工作

这个食谱所需的唯一物品在本章的*技术要求*部分列出。

## 如何做…

使用文件描述符读取文件与写入文件类似。我们将使用`read()`系统调用，而不是使用`write()`系统调用。在我们读取内容之前，我们必须先找出文件的大小。我们可以使用`fstat()`系统调用来获取这个信息，它会给我们关于文件描述符的信息：

1.  将以下代码写入一个文件，并将其命名为`fd-read.c`。注意我们如何使用`fstat()`获取文件信息，然后使用`read()`读取数据。我们仍然使用`open()`系统调用，但这次我们已经移除了`O_CREATE`并将`O_RDRW`更改为`O_RDONLY`以只允许读取。我们将在这里使用缓冲区大小为 4,096，以便能够读取一些更大的文件。这个程序有点长，所以我把它分成了几个步骤。所有步骤中的代码都放在一个文件中。首先，我们从编写所有的`include`行、变量和参数检查开始：

```
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#define MAXSIZE 4096
int main(int argc, char *argv[])
{
   int fd; /* for the file descriptor */
   int maxread; /* the maximum we want to read*/
   off_t filesize; /* for the file size */
   struct stat fileinfo; /* struct for fstat */
   char rbuf[MAXSIZE] = { 0 }; /* the read buffer*/

   if (argc != 2)
   {
      fprintf(stderr, "Usage: %s [path]\n",
         argv[0]);
      return 1;
   }
```

1.  现在，我们编写打开文件描述符的代码，使用`open()`系统调用。我们还添加了一些错误处理，将其包装在一个`if`语句中：

```
   /* open the file in read-only mode and get
      the file size */
   if ( (fd = open(argv[1], O_RDONLY)) == -1 )
   {
      perror("Can't open file for reading");
      return 1;
   }
```

1.  现在，我们编写代码，使用`fstat()`系统调用获取文件的大小。在这里，我们还检查文件的大小是否大于`MAXSIZE`，如果是，我们将`maxread`设置为`MAXSIZE-1`。否则，我们将其设置为文件的大小。然后，我们使用`read()`系统调用读取文件。最后，我们使用`printf()`打印内容：

```
   fstat(fd, &fileinfo);
   filesize = fileinfo.st_size;
   /* determine the max size we want to read
      so we don't overflow the read buffer */
   if ( filesize >= MAXSIZE )
      maxread = MAXSIZE-1;
   else
      maxread = filesize;

   /* read the content and print it */
   if ( (read(fd, rbuf, maxread)) == -1 )
   {
      perror("Can't read file");
      return 1;
   }
   printf("%s", rbuf);
   return 0;
}
```

1.  让我们编译程序：

```
$> make fd-read
gcc -Wall -Wextra -pedantic -std=c99    fd-read.c   -o fd-read
```

1.  让我们尝试在一些文件上运行它，看看我们是否可以读取它们：

```
$> ./fd-read testfile1.txt 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
$> ./fd-read Makefile 
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -std=c99
$> ./fd-read /etc/shadow
Can't open file for reading: Permission denied
$> ./fd-read asdfasdf
Can't open file for reading: No such file or directory
```

## 工作原理...

当我们从文件描述符中读取数据时，我们必须指定要读取多少个字符。在这里，我们必须小心不要溢出缓冲区。我们也不想读取比文件实际包含的更多内容。为了解决所有这些问题，我们首先使用`fstat()`找出文件的大小。该函数给我们提供了与我们之前在`my-stat-v2`程序中使用`stat()`看到的相同的信息。这两个函数`stat()`和`fstat()`做着相同的事情，但它们作用于不同的对象。`stat()`函数直接作用于文件，而`fstat()`作用于文件描述符。由于我们已经打开了正确文件的文件描述符，因此使用它是有意义的。这两个函数都将它们的信息保存到一个名为`stat`的结构体中。

为了不溢出缓冲区，我们检查文件大小和`MAXSIZE`哪个更大。如果文件大小大于或等于`MAXSIZE`，我们使用`MAXSIZE-1`作为要读取的最大字符数。否则，我们使用文件的大小作为最大值。

`read()`系统调用和`write()`接受相同的参数，即文件描述符、缓冲区和要读取的大小（或者在`write()`的情况下是要写入的大小）。

由于我们从文件中读取的是一堆字符，我们可以使用常规的`printf()`将整个缓冲区打印到 stdout。

## 还有更多...

如果您查阅`man 2 fstat`，您会注意到它与`man 2 stat`是同一个手册页。

# 使用文件流写入文件

在本篇中，我们将使用**文件流**而不是文件描述符来写入文件，就像我们在之前的篇章中所做的那样。

与之前我们已经看到的文件描述符 1、2 和 3 以及它们的一些系统调用一样，我们也已经看到了文件流，比如我们创建的一些`printUsage()`函数。我们创建的一些函数接受两个参数，第一个声明为`FILE *stream`。我们提供的参数是 stderr 或 stdout。

但是我们也可以使用文件流来写入文件，这就是本篇中要做的事情。

您可能已经注意到，一些东西一遍又一遍地出现，比如文件描述符和文件流。

使用文件流而不是文件描述符有一些优势。例如，使用文件流，我们可以使用`fprintf()`等函数来写入文件。这意味着有更多和更强大的函数来读写数据。

## 准备工作

对于这个示例，我们只需要本章节“技术要求”部分列出的内容。

## 如何做…

在这里，我们编写一个将文本写入文件的程序。该程序将类似于我们之前使用文件描述符编写的内容。但这次，我们将从标准输入而不是从命令行读取文本。我们还将使用文件流而不是文件描述符来写入文本：

1.  将以下代码写入文件并命名为`stream-write.c`。请注意，尽管我们已经添加了一个`while`循环来从标准输入读取所有内容，但这个程序要小得多。由于我们可以使用在流上操作的所有 C 函数，因此我们不需要使用任何特殊的系统调用来读取、写入等。我们甚至没有包含任何特殊的头文件，除了我们总是包含的`stdio.h`。我们使用`fprintf()`将文本写入文件，就像我们在写入 stdout 或 stderr 时已经看到的那样：

```
#include <stdio.h>
int main(int argc, char *argv[])
{
   FILE *fp; /* pointer to a file stream */
   char linebuf[1024] = { 0 }; /* line buffer */
   if ( argc != 2 )
   {
      fprintf(stderr, "Usage: %s [path]\n", 
         argv[0]);
      return 1;
   }
   /* open file with write mode */
   if ( (fp = fopen(argv[1], "w")) == NULL )
   {
      perror("Can't open file for writing");
      return 1;
   } 

   /*loop over each line and write it to the file*/
   while(fgets(linebuf, sizeof(linebuf), stdin) 
      != NULL)
   {
      fprintf(fp, linebuf);
   }
   fclose(fp); /* close the stream */
   return 0;
}
```

1.  让我们编译程序：

```
$> make stream-write
gcc -Wall -Wextra -pedantic -std=c99    stream-write.c   -o stream-write
```

1.  现在让我们尝试该程序，一种是通过向其输入数据，另一种是通过使用管道重定向数据。在我们使用程序将整个密码文件重定向到新文件后，我们使用`diff`检查它们是否相同，它们应该是相同的。我们还尝试向一个没有权限的目录中写入新文件。当我们按下*Ctrl* + *D*时，我们向程序发送**EOF**，表示不再接收更多数据：

```
$> ./stream-write my-test-file.txt
Hello! How are you doing?
I'm doing just fine, thank you. 
*Ctrl*+*D*
$> cat my-test-file.txt 
Hello! How are you doing?
I'm doing just fine, thank you.
$> cat /etc/passwd | ./stream-write my-test-file.txt
$> tail -n 3 my-test-file.txt 
telegraf:x:999:999::/etc/telegraf:/bin/false
_rpc:x:103:65534::/run/rpcbind:/usr/sbin/nologin
systemd-coredump:x:997:997:systemd Core Dumper:/:/usr/sbin/nologin
$> diff /etc/passwd my-test-file.txt
$> ./stream-write /a-new-file.txt
Can't open file for writing: Permission denied
```

## 工作原理…

您可能已经注意到，尽管我们在本章的前面编写的相应文件描述符版本要添加一个`while`循环来从标准输入读取所有内容，但这个程序要比那个版本简短得多。

我们首先创建一个指向文件流的指针，使用`FILE *fp`。然后我们创建一个用于每行的缓冲区。

然后，我们使用`fopen()`打开文件流。该函数需要两个参数，文件名和模式。这里的模式也更容易设置，只需使用`"w"`表示写入。

之后，我们使用`while`循环来循环处理来自标准输入的每一行输入。在每次迭代中，我们使用`fprintf()`将当前行写入文件。作为`fprintf()`的第一个参数，我们使用文件流指针，就像我们在程序顶部的`if`语句中使用 stderr 一样。

在程序返回之前，我们使用`fclose()`关闭文件流。关闭流并不是严格必要的，但以防万一做这件事是件好事。

## 另请参阅

如果您想深入了解，可以在`man 3 fopen`中找到大量信息。

有关文件描述符和文件流之间区别的更深入解释，请参阅 GNU libc 手册：[`www.gnu.org/software/libc/manual/html_node/Streams-and-File-Descriptors.html`](https://www.gnu.org/software/libc/manual/html_node/Streams-and-File-Descriptors.html)。

流的另一个重要方面是它们是有缓冲的。有关流缓冲的更多信息，请参阅 GNU libc 手册的以下网址：[`www.gnu.org/software/libc/manual/html_node/Buffering-Concepts.html`](https://www.gnu.org/software/libc/manual/html_node/Buffering-Concepts.html)。

# 使用流从文件中读取

现在我们知道如何使用流写入文件，我们将学习如何使用流读取文件。在这个示例中，我们将编写一个类似于上一个示例的程序。但这次，我们将逐行从文件中读取并将其打印到标准输出。

掌握流的写入和读取将使您能够在 Linux 中做很多事情。

## 准备工作

您只需要本章节“技术要求”部分列出的内容。

## 如何做…

在这里，我们将编写一个与上一个示例非常相似的程序，但它将从文件中读取文本。该程序的原理与上一个示例相同：

1.  在文件中写入以下代码，并将其保存为`stream-read.c`。注意这个程序是多么相似。我们已经改变了写入模式(`"w"`)为读取模式(`"r"`)，当使用`fopen()`打开流时。在`while`循环中，我们从文件指针`fp`而不是标准输入中读取。在`while`循环中，我们打印缓冲区中的内容，也就是当前行：

```
#include <stdio.h>
int main(int argc, char *argv[])
{
   FILE *fp; /* pointer to a file stream */
   char linebuf[1024] = { 0 }; /* line buffer */
   if ( argc != 2 )
   {
      fprintf(stderr, "Usage: %s [path]\n", 
         argv[0]);
      return 1;
   }
   /* open file with read mode */
   if ( (fp = fopen(argv[1], "r")) == NULL )
   {
      perror("Can't open file for reading");
      return 1;
   } 

   /* loop over each line and write it to stdout */
   while(fgets(linebuf, sizeof(linebuf), fp) 
      != NULL)
   {
      printf("%s", linebuf);
   }
   fclose(fp); /* close the stream */
   return 0;
}
```

1.  编译程序：

```
$> make stream-read
gcc -Wall -Wextra -pedantic -std=c99    stream-read.c   -o stream-read
```

1.  现在我们可以在一些文件上尝试这个程序。这里我在之前创建的测试文件和 Makefile 上尝试它：

```
$> ./stream-read testfile1.txt 
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
$> ./stream-read Makefile 
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -std=c99
```

## 它是如何工作的…

正如你可能已经注意到的，这个程序与上一个配方非常相似。但是，我们不是以写入模式(`"w"`)打开文件，而是以读取模式(`"r"`)打开文件。文件指针看起来一样，以及行缓冲区和错误处理。

为了读取每一行，我们使用`fgets()`循环遍历文件流。正如你可能已经注意到的，在这个和上一个配方中，我们没有使用`sizeof(linebuf)-1`，只使用了`sizeof(linebuf)`。这是因为`fgets()`只读取比我们给它的大小*少一个*。

## 还有更多…

有很多类似的函数，比如`fgets()`。你可以通过阅读它的手册页`man 3 fgets`找到所有这些函数。

# 使用流读取和写入二进制数据

有时候我们需要将程序中的变量或数组保存到文件中。例如，如果我们为仓库制作一个库存管理程序，我们不希望每次启动程序时都重新编写整个仓库库存。这将违背程序的初衷。使用流，可以轻松地将变量保存为二进制数据文件以供以后检索。

在本章中，我们将编写两个小程序：一个要求用户输入两个浮点数，将它们保存在一个数组中，并将它们写入文件，另一个程序重新读取该数组。

## 准备工作

对于这个配方，你只需要 GCC 编译器、Make 工具和通用 Makefile。

## 如何做…

在这个配方中，我们将编写两个小程序：一个用于写入，一个用于读取二进制数据。数据是一个浮点数数组：

1.  在文件中写入以下代码，并将其保存为`binary-write.c`。注意我们以*写入*模式和*二进制*模式打开文件，这由`fopen()`的第二个参数`"wb"`表示。在二进制模式下，我们可以将变量、数组和结构写入文件。这个程序中的数组将被写入到当前工作目录中名为`my-binary-file`的文件中。当我们使用`fwrite()`写入二进制数据时，我们必须指定单个元素的大小（在这种情况下是`float`）以及我们想要写入的元素数量。`fwrite()`的第二个参数是单个元素的大小，第三个参数是元素的数量：

```
#include <stdio.h>
int main(void)
{
   FILE *fp;
   float x[2];
   if ( (fp = fopen("my-binary-file", "wb")) == 0 )
   {
      fprintf(stderr, "Can't open file for "
         "writing\n");
      return 1;
   }
   printf("Type two floating point numbers, "
      "separated by a space: ");
   scanf("%f %f", &x[0], &x[1]);
   fwrite(&x, sizeof(float), 
      sizeof(x) / sizeof(float), fp);
   fclose(fp);
   return 0;
}
```

1.  在继续之前，让我们编译这个程序：

```
$> make binary-write
gcc -Wall -Wextra -pedantic -std=c99    binary-write.c   -o binary-write
```

1.  让我们尝试运行程序，并验证它是否写入了二进制文件。由于它是一个二进制文件，我们无法使用`more`等程序来读取它。但是，我们可以使用一个名为`hexdump`的程序来查看它：

```
$> ./binary-write 
Type two floating point numbers, separated by a space: 3.14159 2.71828
$> file my-binary-file 
my-binary-file: data
$> hexdump -C my-binary-file 
00000000  d0 0f 49 40 4d f8 2d 40            |..I@M.-@|
00000008
```

1.  现在是时候编写从文件中重新读取数组的程序了。在文件中写入以下代码，并将其保存为`binary-ready.c`。请注意，我们在这里使用了`"rb"`，表示*读取*和*二进制*。`fread()`的参数与`fwrite()`相同。另外，请注意我们需要在这里创建一个相同类型和长度的数组。我们将从二进制文件中读取数据到该数组中：

```
#include <stdio.h>
int main(void)
{
   FILE *fp;
   float x[2];
   if ( (fp = fopen("my-binary-file", "rb")) == 0 )
   {
      fprintf(stderr, "Can't open file for "
         "reading\n");
      return 1;
   }
   fread(&x, sizeof(float), 
      sizeof(x) / sizeof(float), fp);
   printf("The first number was: %f\n", x[0]);
   printf("The second number was: %f\n", x[1]);
   fclose(fp);
   return 0;
}
```

1.  现在，让我们编译这个程序：

```
$> make binary-read
gcc -Wall -Wextra -pedantic -std=c99    binary-read.c   -o binary-read
```

1.  最后，让我们运行程序。请注意，这里打印的数字与我们给`binary-write`的数字相同：

```
$> ./binary-read 
The first number was: 3.141590
The second number was: 2.718280
```

## 它是如何工作的…

重要的是`fwrite()`和`fread()`，更具体地说是我们指定的大小：

```
fwrite(&x, sizeof(float), sizeof(x) / sizeof(float), fp);
```

首先，我们有`x`数组。接下来，我们指定单个元素或项目的大小。在这种情况下，我们使用`sizeof(float)`来获取大小。然后，作为第三个参数，我们指定这些元素或项目的数量。在这里，我们不只是输入一个字面上的`2`，而是通过取数组的完整大小并除以一个浮点数的大小来计算项目的数量。这是通过`sizeof(x) / sizeof(float)`完成的。在这种情况下，这给了我们 2。

更好地计算项目而不只是设置一个数字的原因是为了避免在将来更新代码时出现错误。如果我们在几个月内将数组更改为 6 个项目，很可能会忘记更新`fread()`和`fwrite()`的参数。

## 还有更多…

如果我们事先不知道数组包含多少个浮点数，我们可以用以下代码行来计算出来。我们将在本章后面学习更多关于`fseek()`的知识：

```
fseek(fp, 0, SEEK_END); /* move to the end of the file */
```

```
bytes = ftell(fp); /* the total number of bytes */
```

```
rewind(fp); /* go back to the start of the file */
```

```
items = bytes / sizeof(float); /*number of items (floats)*/
```

# 使用`lseek()`在文件内移动

在这个食谱中，我们将学习如何使用`lseek()`在文件内移动。这个函数操作`lseek()`，我们可以在文件描述符内自由移动（或**寻找**）。这样做可以很方便，如果我们只想读取文件的特定部分，或者我们想返回并读取一些数据两次等。

在这个食谱中，我们将修改我们之前的程序，名为`fd-read.c`，以指定我们想要开始阅读的位置。我们还使用户可以指定从该位置读取多少个字符。

## 准备工作

为了更容易理解这个食谱，我鼓励你在阅读这个之前，先阅读本章中名为*使用文件描述符从文件中读取*的食谱。

## 操作步骤…

我们将在这里编写的程序将使用文件描述符读取文件。用户还必顶一个读取应该从哪里开始的起始位置。用户还可以选择指定从该位置读取多少个字符：

1.  写下以下代码并保存在一个名为`fd-seek.c`的文件中。注意在我们进行`read()`之前添加了`lseek()`。我们还添加了一个额外的检查（`else if`）来检查用户是否读取的字符数超过了缓冲区的容量。当我们将文件打印到标准输出时，在`printf()`中添加了一个换行符。否则，当我们指定要读取多少个字符时，不会有新的一行，提示符会停留在同一行上。这个程序也相当长，所以我把它分成了几个步骤。请记住，所有步骤都放在同一个文件中。让我们从变量开始并检查参数的数量：

```
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#define MAXSIZE 4096
int main(int argc, char *argv[])
{
   int fd; /* for the file descriptor */
   int maxread; /* the maximum we want to read*/
   off_t filesize; /* for the file size */
   struct stat fileinfo; /* struct for fstat */
   char rbuf[MAXSIZE] = { 0 }; /* the read buffer */
   if (argc < 3 || argc > 4)
   {
      fprintf(stderr, "Usage: %s [path] [from pos] "
         "[bytes to read]\n", argv[0]);
      return 1;
   }
```

1.  现在我们使用`open()`系统调用打开文件。就像以前一样，我们通过将其包装在`if`语句中来检查系统调用是否出错：

```
   /* open the file in read-only mode and get
      the file size */
   if ( (fd = open(argv[1], O_RDONLY)) == -1 )
   {
      perror("Can't open file for reading");
      return 1;
   }
```

1.  现在，我们使用`fstat()`系统调用获取文件的大小。在这里，我们还检查文件是否大于`MAXSIZE`，如果是，我们将`maxread`设置为`MAXSIZE-1`。在`else if`中，我们检查用户是否提供了第三个参数（要读取多少），并将`maxread`设置为用户输入的值：

```
   fstat(fd, &fileinfo);
   filesize = fileinfo.st_size;
   /* determine the max size we want to read
      so we don't overflow the read buffer */
   if ( filesize >= MAXSIZE )
   {
      maxread = MAXSIZE-1;
   }
   else if ( argv[3] != NULL )
   {
      if ( atoi(argv[3]) >= MAXSIZE )
      {
         fprintf(stderr, "To big size specified\n");
         return 1;
      }
      maxread = atoi(argv[3]);
   }
   else
   {
      maxread = filesize;
   }
```

1.  最后，我们编写代码使用`lseek()`移动读取位置。然后，我们使用`read()`读取内容并用`printf()`打印出来：

```
   /* move the read position */
   lseek(fd, atoi(argv[2]), SEEK_SET);
   /* read the content and print it */
   if ( (read(fd, rbuf, maxread)) == -1 )
   {
      perror("Can't read file");
      return 1;
   }
   printf("%s\n", rbuf);
   return 0;
}
```

1.  现在编译程序：

```
$> make fd-seek
gcc -Wall -Wextra -pedantic -std=c99    fd-seek.c   -o fd-seek
```

1.  让我们尝试一下这个程序。在这里，我们读取当前目录中的密码文件和通用 Makefile：

```
$> ./fd-seek /etc/passwd 40 100
:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr
$> ./fd-seek Makefile 10
AGS=-Wall -Wextra -pedantic -std=c99
$> ./fd-seek Makefile
Usage: ./fd-seek [path] [from pos] [bytes to read]
```

## 工作原理…

`lseek()`函数将*读取头*（有时称为*光标*）移动到我们指定的位置。然后光标保持在那个位置，直到我们开始`read()`。为了只读取我们指定的第三个参数作为字符数，我们将该参数赋值给`maxread`。由于`read()`不会读取超过`maxread`（`read()`的第三个参数）的字符，只有这些字符会被读取。如果我们没有给程序第三个参数，`maxread`将设置为文件的大小或`MAXSIZE`，以较小者为准。

`lseek()`的第三个参数`SEEK_SET`是光标应该相对于我们给出的第二个参数的位置。在这种情况下，使用`SEEK_SET`意味着位置应该设置为我们指定的第二个参数。如果我们想要相对于当前位置移动位置，我们将使用`SEEK_CUR`。如果我们想要相对于文件末尾移动光标，我们将使用`SEEK_END`。

# 使用`fseek()`在文件中移动

现在我们已经看到了如何使用`lseek()`，我们可以看看如何在文件流中使用`fseek()`。在这个示例中，我们将编写一个类似于上一个示例的程序，但现在我们将使用文件流。这里还有另一个区别，即我们如何指定要读取多长时间。在上一个示例中，我们将第三个参数指定为要读取的字符或字节数。但在这个示例中，我们将指定一个位置，即*起始位置*和*结束位置*。

## 准备工作

我建议您在阅读本章前面的*使用流从文件中读取*示例之前阅读本节。这将让您更好地理解这里发生了什么。

## 如何做…

我们将编写一个程序，从给定位置读取文件，可选地到达结束位置。如果没有给出结束位置，则读取文件直到结束：

1.  在文件中写入以下代码，并将其保存为`stream-seek.c`。这个程序类似于`stream-read.c`，但增加了指定起始位置和可选的结束位置的能力。请注意，我们已经添加了`fseek()`来设置起始位置。为了中止读取，当我们达到结束位置时，我们使用`ftell()`告诉我们当前位置。如果到达结束位置，我们就跳出`while`循环。此外，我们不再读取整行，而是读取单个字符。我们使用`fgetc()`来实现这一点。我们还打印单个字符而不是整个字符串（行）。我们使用`putchar()`来实现这一点。循环结束后，我们打印一个换行字符，这样提示就不会出现在与输出相同的行上：

```
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
   int ch; /* for each character */
   FILE *fp; /* pointer to a file stream */
   if ( argc < 3 || argc > 4 )
   {
      fprintf(stderr, "Usage: %s [path] [from pos]"
         " [to pos]\n", argv[0]);
      return 1;
   }

   /* open file with read mode */
   if ( (fp = fopen(argv[1], "r")) == NULL )
   {
      perror("Can't open file for reading");
      return 1;
   } 

   fseek(fp, atoi(argv[2]), SEEK_SET);
   /* loop over each line and write it to stdout */
   while( (ch = fgetc(fp)) != EOF )
   {
      if ( argv[3] != NULL)
      {
         if ( ftell(fp) >= atoi(argv[3]) )
         {
            break;
         }
      }
      putchar(ch);
   }
   printf("\n");
   fclose(fp); /* close the stream */
   return 0;
}
```

1.  现在让我们来编译它：

```
$> make stream-seek
gcc -Wall -Wextra -pedantic -std=c99    stream-seek.c   -o stream-seek
```

1.  让我们在一些文件上试一试。我们尝试两种可能的组合：只有起始位置，以及起始和结束位置：

```
$> ./stream-seek /etc/passwd 2000 2100
24:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
Debian-exim:x:120:126::/var/spool/exim4:/bin/false
s
$> ./stream-seek Makefile 20
-Wextra -pedantic -std=c99
```

## 工作原理…

`fseek()`函数的工作方式与我们在上一个示例中看到的`lseek()`类似。我们指定`SEEK_SET`来告诉`fseek()`寻找绝对位置，并将位置指定为第二个参数。

该程序类似于`stream-read.c`，但我们已经改变了程序的读取方式。我们不再读取整行，而是读取单个字符。这样我们就可以在指定的结束位置停止读取。如果我们逐行读取，这是不可能的。因为我们改变了按字符读取文件的行为，所以我们也改变了打印文件的方式。现在我们使用`putchar()`逐个打印每个字符。

每个字符后，我们检查是否在指定的结束位置上或以上。如果是，我们就跳出循环并结束整个读取。

## 还有更多…

存在一整套与`fseek()`相关的函数。您可以通过阅读`man 3 fseek`手册页面找到它们。


# 第六章：生成进程和使用作业控制

在本章中，我们将了解系统上如何创建进程，哪个进程是第一个进程，以及所有进程如何相互关联。然后，我们将学习 Linux 中涉及进程和进程管理的许多术语。之后，我们将学习如何分叉新进程以及**僵尸**和**孤儿**是什么。在本章结束时，我们将学习**守护进程**是什么以及如何创建它，然后学习信号是什么以及如何实现它们。

了解系统上如何创建进程对于实现良好的守护进程、处理安全性和创建高效的程序至关重要。它还将让您更好地了解整个系统。在本章中，我们将涵盖以下示例：

+   探索进程是如何创建的

+   在 Bash 中使用作业控制

+   使用信号控制和终止进程

+   用`execl()`替换进程中的程序

+   分叉进程

+   在分叉进程中执行新程序

+   使用`system()`启动新进程

+   创建僵尸进程

+   了解孤儿进程是什么

+   创建守护进程

+   实现信号处理程序

让我们开始吧！

# 技术要求

在本章中，您将需要 GCC 编译器和 Make 工具。我们在[*第一章*]（B13043_01_Final_SK_ePub.xhtml#_idTextAnchor020）中安装了这些工具，获取必要的工具并编写我们的第一个 Linux 程序。

您还需要一个名为`pstree`的新程序来完成本章。您可以使用软件包管理器安装它。如果您使用的是 Debian 或 Ubuntu，可以使用`sudo apt install psmisc`进行安装。另一方面，如果您使用的是 Fedora 或 CentOS，可以使用`sudo dnf install psmisc`进行安装。

您还需要我们在[*第三章*]（B13043_03_Final_SK_ePub.xhtml#_idTextAnchor097）中编写的通用`Makefile`。Makefile 也可以在 GitHub 上找到，本章的所有代码示例也可以在[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch6`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch6)找到。

查看以下链接以查看代码演示视频：[`bit.ly/3cxY0eQ`](https://bit.ly/3cxY0eQ)

# 探索进程是如何创建的

在深入了解如何创建进程和守护进程之前，我们需要对进程有一个基本的理解。获得这种理解的最佳方法是查看系统上已经运行的进程，这就是我们将在本示例中要做的事情。

系统上的每个进程都是通过从另一个进程*生成*（forked）而开始其生命周期的。在 Unix 和 Linux 系统上使用的第一个进程历史上一直是`init`进程，现代 Linux 发行版已将其替换为**systemd**。它们都具有相同的目的；启动系统的其余部分。

典型的**进程树**可能如下所示，其中用户通过终端登录（即，如果我们跳过 X Window 登录的复杂性）：

```
|- systemd (1)
```

```
  \- login (6384)
```

```
    \- bash (6669)
```

```
      \- more testfile.txt (7184)
```

进程 ID 是括号中的数字。`systemd`（或一些旧系统上的`init`）有一个`init`，即使使用的是`systemd`。在这种情况下，`init`只是指向`systemd`的链接。仍然有一些使用`init`的 Linux 系统。

当涉及编写系统程序时，深入了解进程**生成**是至关重要的。例如，当我们想要创建一个守护进程时，我们经常会生成一个新进程。还有许多其他用例，我们必须生成进程或从现有进程执行新程序。

## 准备就绪

对于这个示例，您将需要`pstree`。`pstree`的安装说明列在本章的*技术要求*部分中。

## 如何做…

在这个示例中，我们将查看我们的系统和它运行的进程。我们将使用`pstree`来获得这些进程的可视化表示。让我们开始吧：

1.  首先，我们需要一种方法来获取我们当前的进程 ID。`$$`环境变量包含当前 shell 的**PID**。请注意，PID 在每个系统上以及从一次到另一次都会有所不同：

```
$> echo $$
18817
```

1.  现在，让我们用`pstree`来查看我们当前的进程，以及它的父进程和子进程。父进程是启动该进程的进程，而子进程是其下的任何进程：

```
$> pstree -A -p -s $$
systemd(1)---tmux (4050)---bash(18817)---pstree(18845)
```

1.  `pstree`命令的输出在您的计算机上很可能会有所不同。您可能有`xterm`、`konsole`、`mate-terminal`或类似的东西，而不是`tmux`。`-A`选项表示使用 ASCII 字符打印行，`-p`选项表示打印 PID 号，`-s`选项表示我们要显示所选进程的父进程（在我们的情况下是`$$`）。在我的例子中，`tmux`是`systemd`的子进程，`bash`是`tmux`的子进程，`pstree`是`bash`的子进程。

1.  一个进程也可以有多个子进程。例如，我们可以在 Bash 中启动多个进程。在这里，我们将启动三个`sleep`进程。每个`sleep`进程将休眠 120 秒。然后我们将打印另一个`pstree`。在这个例子中，`pstree`和三个`sleep`进程都是`bash`的子进程：

```
$> sleep 120 &
[1] 21902
$> sleep 120 &
[2] 21907
$> sleep 120 &
[3] 21913
$> pstree -A -p -s $$
systemd(1)---tmux (4050)---bash(18817)-+-pstree(21919)
                                       |-sleep(21902)
                                       |-sleep(21907)
                                       `-sleep(21913)
```

1.  在本章的开头，我们提供了一个显示名为`login`的进程的示例进程树。该进程最初是作为管理系统 TTY 的进程`getty`启动的。`getty`/`login`的概念，切换到 TTY3，使用*Ctrl*+*Alt*+*F3*进行激活。然后，返回到 X（通常在*Ctrl*+*Alt*+*F7*或*Ctrl*+*Alt*+*F1*）。在这里，我们将使用`grep`和`ps`来查找 TTY3 并记录其 PID。`ps`程序用于查找和列出系统上的进程。然后，我们将使用用户在 TTY3 上登录（*Ctrl*+*Alt*+*F3*）。之后，我们需要再次返回到我们的 X Window 会话（和我们的终端），并使用`grep`来找到我们从 TTY3 中记录的 PID。该进程中的程序现在已被替换为`login`。换句话说，一个进程可以替换其程序：

```
Ctrl+Alt+F3
login: 
Ctrl+Alt+F7
$> ps ax | grep tty3
9124 tty3     Ss+    0:00 /sbin/agetty -o -p -- \u --
noclear tty3 linux
Ctrl+Alt+F3
login: jake
Password: 
$> 
Ctrl+Alt+F7
$> ps ax | grep 9124
9124 tty3     Ss     0:00 /bin/login -p –
```

## 工作原理…

在这个教程中，我们学习了关于 Linux 系统上进程的几个重要概念。我们将需要这些知识继续前进。首先，我们了解到所有进程都是从现有进程中生成的。第一个进程是`init`。在较新的 Linux 发行版中，这是指向`systemd`的符号链接。然后，`systemd`在系统上生成几个进程，比如`getty`，来处理终端。当用户开始在 TTY 上登录时，`getty`会被`login`替换，这个程序处理登录。当用户最终登录时，`login`进程为用户生成一个 shell，比如 Bash。然后，每当用户执行一个程序时，Bash 会生成一个自身的副本，并用用户执行的程序替换它。

为了澄清一下进程/程序术语：`getty`/`login`示例。

在这个教程中使用 TTY3 的原因是，我们可以通过`getty`/`login`获得一个*真正的*登录过程，而在通过 X Window 会话或 SSH 登录时我们无法获得。

进程 ID 表示为 PID。父进程 ID 表示为`1`）。

我们还了解到一个进程可以有多个子进程，就像`sleep`进程的示例一样。我们在`sleep`进程的末尾使用`&`符号启动了`sleep`进程。这个&符号告诉 shell 我们要在后台启动该进程。

## 还有更多…

TTY 的首字母缩写来自于过去的实际*电传打字机*连接到机器上。电传打字机是一种看起来像打字机的终端。您在打字机上输入命令，然后在纸上读取响应。对于任何对电传打字机感兴趣的人，哥伦比亚大学在[`www.columbia.edu/cu/computinghistory/teletype.html`](http://www.columbia.edu/cu/computinghistory/teletype.html)上有一些令人兴奋的图片和信息。

# 在 Bash 中使用作业控制

作业控制不仅能让你更好地理解前台和后台进程，还能让你在终端上工作时更加高效。能够将一个进程放到后台可以让你的终端做其他任务。

## 准备工作

这个教程不需要特别的要求，除了 Bash shell。Bash 通常是默认的 shell，所以你很可能已经安装了它。

## 操作方法…

在这个教程中，我们将启动和停止几个进程，将它们发送到后台，并将它们带回前台。这将让我们了解后台和前台进程。让我们开始吧：

1.  之前，我们已经看到如何使用&在后台启动一个进程。我们将在这里重复这个步骤，但我们还将列出当前正在运行的作业，并将其中一个带到前台。我们将在这里启动的第一个后台进程是`sleep`，而另一个是手册页面：

```
$> sleep 300 &
[1] 30200
$> man ls &
[2] 30210
```

1.  现在我们在`jobs`中有两个进程：

```
$> jobs
[1]-  Running                 sleep 300 &
[2]+  Stopped                 man ls
```

1.  `sleep`进程处于运行状态，这意味着程序中的秒数正在减少。`man ls`命令已经停止了。`man`命令正在等待你对它做一些事情，因为它需要一个终端。所以，现在它什么也不做。我们可以使用`fg`命令（`fg`命令是`jobs`列表中的作业 ID）将它带到前台：

```
$> fg 2
```

1.  按*Q*退出手册页面。`man ls`将出现在屏幕上。

1.  现在，使用`fg 1`将`sleep`进程带到前台。它只显示`sleep 300`，没有更多的信息。但现在，程序在前台运行。这意味着我们现在可以按下*Ctrl*+*Z*来停止程序：

```
sleep 300
Ctrl+Z
[1]+  Stopped                 sleep 300
```

1.  程序已经停止，这意味着它不再倒计时。我们现在可以再次用`fg 1`将其带回前台并让它完成。

1.  现在上一个进程已经完成，让我们开始一个新的`sleep`进程。这次，我们可以在前台启动它（省略了&）。然后，我们可以按下*Ctrl*+*Z*来停止程序。列出作业并注意程序处于停止状态：

```
$> sleep 300
Ctrl+Z
[1]+  Stopped                 sleep 300
$> jobs
[1]+  Stopped                 sleep 300
```

1.  现在，我们可以使用`bg`命令在后台继续运行程序（`bg`代表*background*）：

```
$> bg 1
[1]+ sleep 300 &
$> jobs
[1]+  Running                 sleep 300 &
```

1.  我们还可以使用一个叫做`pgrep`的命令来找到程序的 PID。`pgrep`的名称代表*Process Grep*。`-f`选项允许我们指定完整的命令，包括它的选项，以便我们得到正确的 PID：

```
$> pgrep -f "sleep 300"
4822
```

1.  现在我们知道了 PID，我们可以使用`kill`来终止程序：

```
$> kill 4822
$> Enter
[1]+  Terminated              sleep 300
```

1.  我们也可以使用`pkill`来终止一个程序。在这里，我们将启动另一个进程，并使用`pkill`来终止它。这个命令和`pgrep`使用相同的选项：

```
$> sleep 300 &
[1] 6526
$> pkill -f "sleep 300"
[1]+  Terminated              sleep 300
```

## 工作原理…

在这个教程中，我们学习了后台进程、前台进程、停止和运行的作业、终止进程等基本概念。这些是 Linux 作业控制中使用的一些基本概念。

当我们用`kill`杀死进程时，`kill`向后台进程发送了一个信号。`kill`的默认信号是`TERM`信号。`TERM`信号是 15 号信号。一个无法处理的信号——总是终止程序的信号是 9 号信号，或者`KILL`信号。我们将在下一个教程中更深入地介绍信号处理。

# 使用信号来控制和终止进程

现在我们对进程有了一些了解，是时候转向信号并学习如何使用信号来终止和控制进程了。在这个教程中，我们还将编写我们的第一个 C 程序，其中将包含一个信号处理程序。

## 准备工作

对于这个教程，你只需要本章节*技术要求*部分列出的内容。

## 操作方法…

在这个教程中，我们将探讨如何使用信号来控制和终止进程。让我们开始吧：

1.  让我们首先列出我们可以使用`kill`命令发送给进程的信号。从这个命令得到的列表相当长，所以这里没有包含。最有趣和使用的信号是前 31 个：

```
$> kill -L
```

1.  让我们看看这些信号是如何工作的。我们可以向一个进程发送`STOP`信号（编号 19），这与我们在`sleep`中按下*Ctrl*+*Z*看到的效果相同。但是这里，我们直接向一个后台进程发送`STOP`信号：

```
$> sleep 120 &
[1] 16392
$> kill -19 16392
 [1]+  Stopped                 sleep 120
$> jobs
[1]+  Stopped                 sleep 120
```

1.  现在，我们可以通过发送`CONT`信号（**continue**的缩写）来继续进程。如果愿意，我们也可以输入信号的名称，而不是它的编号：

```
$> kill -CONT 16392
$> jobs
[1]+  Running                 sleep 120 &
```

1.  现在，我们可以通过发送`KILL`信号（编号 9）来终止进程：

```
$> kill -9 16392
$> Enter
[1]+  Killed                  sleep 120
```

1.  现在，让我们创建一个根据不同信号执行操作并忽略（或阻塞）*Ctrl*+*C*（中断信号）的小程序。`USR1`和`USR2`信号非常适合这个目的。将以下代码写入一个文件并保存为`signals.c`。这里将这段代码分成了多个步骤，但所有代码都放在这个文件中。要在程序中注册信号处理程序，我们可以使用`sigaction()`系统调用。由于`sigaction()`及其相关函数不包含在严格的 C99 中，我们需要定义`_POSIX_C_SOURCE`。我们还需要包含必要的头文件，编写处理程序函数原型，并开始`main()`函数：

```
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
void sigHandler(int sig);
int main(void)
{
```

1.  现在，让我们创建一些我们需要的变量和结构。我们将创建的`sigaction`结构`action`是为了`sigaction()`系统调用。在代码中稍后一点，我们设置它的成员。首先，我们必须将`sa_handler`设置为我们的函数，当接收到信号时将执行该函数。其次，我们使用`sigfillset()`将`sa_mask`设置为所有信号。这将在执行我们的信号处理程序时忽略所有信号，防止它被中断。第三，我们将`sa_flags`设置为`SA_RESTART`，这意味着任何中断的系统调用将被重新启动：

```
    pid_t pid; /* to store our pid in */
    pid = getpid(); /* get the pid */
    struct sigaction action; /* for sigaction */
    sigset_t set; /* signals we want to ignore */
    printf("Program running with PID %d\n", pid);
    /* prepare sigaction() */
    action.sa_handler = sigHandler;
    sigfillset(&action.sa_mask);
    action.sa_flags = SA_RESTART;
```

1.  现在，是时候使用`sigaction()`注册信号处理程序了。`sigaction()`的第一个参数是我们想要捕获的信号，第二个参数是新操作的结构，第三个参数给出了旧操作。如果我们对旧操作不感兴趣，我们将其设置为`NULL`。操作必须是`sigaction`结构：

```
    /* register two signal handlers, one for USR1
       and one for USR2 */
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);
```

1.  记住我们希望程序忽略*Ctrl*+*C*（中断信号）吗？这可以通过在应该忽略信号的代码之前调用`sigprocmask()`来实现。但首先，我们必须创建一个包含所有应该忽略/阻塞的信号的*信号集*。首先，我们将使用`sigemptyset()`清空集合，然后使用`sigaddset()`添加所需的信号。`sigaddset()`函数可以多次调用以添加更多的信号。`sigprocmask()`的第一个参数是行为，这里是`SIG_BLOCK`。第二个参数是信号集，而第三个参数可以用于检索旧集。但是，在这里，我们将其设置为`NULL`。之后，我们开始无限的`for`循环。循环结束后，我们再次解除信号集的阻塞。在这种情况下，这是不必要的，因为我们将退出程序，但在其他情况下，建议在我们已经过了应该忽略它们的代码部分后解除信号的阻塞：

```
    /* create a "signal set" for sigprocmask() */
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    /* block SIGINT and run an infinite loop */
    sigprocmask(SIG_BLOCK, &set, NULL);
    /* infinite loop to keep the program running */
    for (;;)
    {
        sleep(10);
    }
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    return 0;
}
```

1.  最后，让我们编写将在`SIGUSR1`和`SIGUSR2`上执行的函数。该函数将打印接收到的信号：

```
void sigHandler(int sig)
{
    if (sig == SIGUSR1)
    {
        printf("Received USR1 signal\n");
    }
    else if (sig == SIGUSR2)
    {
        printf("Received USR2 signal\n");
    }
}
```

1.  让我们编译程序：

```
$> make signals
gcc -Wall -Wextra -pedantic -std=c99    signals.c   -o
 signals
```

1.  运行程序，可以在单独的终端或者在同一个终端的后台运行。请注意，我们在这里使用`kill`命令的信号名称；这比跟踪数字要容易一些：

```
$> ./signals &
[1] 25831
$> Program running with PID 25831
$> kill -USR1 25831
Received USR1 signal
$> kill -USR1 25831
Received USR1 signal
$> kill -USR2 25831
$> kill -USR2 25831
Received USR2 signal
$> Ctrl+C
^C
$> kill -USR1 25831
Received USR1 signal
$> kill -TERM 25831
$> ENTER 
[1]+  Terminated              ./signals
```

## 工作原理…

首先，我们探索了许多`TERM`、`KILL`、`QUIT`、`STOP`、`HUP`、`INT`、`STOP`和`CONT`，就像我们在这里看到的那样。

然后，我们使用`STOP`和`CONT`信号来实现与上一个示例相同的效果；也就是说，停止和继续运行后台进程。在上一个示例中，我们使用`bg`来继续在后台运行进程，而要停止进程，我们按下*Ctrl*+*Z*。这一次，我们不需要将程序打开在前台来停止它；我们只需用`kill`发送`STOP`信号。

之后，我们继续编写了一个 C 程序，捕获了两个信号`USR1`和`USR2`，并阻止了`SIGINT`信号（*Ctrl*+*C*）。根据我们发送给程序的信号，将打印不同的文本。我们通过实现信号处理程序来实现这一点。一个`sigaction()`函数。

在调用`sigaction()`系统调用之前，我们必须使用有关处理程序函数的信息填充`sigaction`结构，该结构在处理程序执行期间忽略的信号，以及它应该具有的行为。

信号集，无论是 sigaction 的`sa_mask`还是`sigprocmask()`，都是使用`sigset_t`类型创建的，并通过以下函数调用进行操作（在这里，我们假设使用了名为`s`的`sigset_t`变量：

+   `sigemptyset(&s);`清除`s`中的所有信号

+   `sigaddset(&s, SIGUSR1);`将`SIGUSR1`信号添加到`s`

+   `sigdelset(&s, SIGUSR1);`从`s`中删除`SIGUSR`信号

+   `sigfillset(&s);`设置`s`中的所有信号

+   `sigismember(&s, SIGUSR1);`找出`SIGUSR1`是否是`s`的成员（在我们的示例代码中未使用）

要在进程启动时打印进程的 PID，我们必须使用`getpid()`系统调用来获取 PID。我们将 PID 存储在`pid_t`类型的变量中，就像我们之前看到的那样。

## 另请参阅

在`kill`、`pkill`、`sigprocmask()`和`sigaction()`系统调用的手册页中有很多有用的信息。我建议您使用以下命令阅读它们：

+   `man 1 kill`

+   `man 1 pkill`

+   `man 2 sigprocmask`

+   `man 2 sigaction`

还有一个更简单的系统调用，称为`signal()`，也用于信号处理。如今，这个系统调用基本上被认为是不推荐使用的。但如果您感兴趣，可以在`man 2 signal`中阅读相关信息。

# 使用 execl()在进程中替换程序

在本章的开头，我们看到当用户登录时，`getty`被`login`替换。在这个示例中，我们将编写一个小程序，正好可以做到这一点——用新程序替换其程序。这个系统调用被称为`execl()`。

了解如何使用`execl()`使您能够编写在现有进程内执行新程序的程序。它还使您能够在生成的进程中启动新程序。当我们启动一个新进程时，我们可能希望用新程序替换该副本。因此，理解`execl()`是至关重要的。

## 准备就绪

您需要阅读本章的前三个示例，才能充分理解这个示例。本示例的其他要求在本章的*技术要求*部分中提到；例如，您将需要`pstree`工具。

您还需要两个终端或两个终端窗口。在其中一个终端中，我们将运行程序，而在另一个终端中，我们将查看`pstree`以查看进程。

## 如何做…

在这个示例中，我们将编写一个小程序，用它替换进程中正在运行的程序。让我们开始吧：

1.  在文件中编写以下代码并将其保存为`execdemo.c`：

```
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
int main(void)
{
   printf("My PID is %d\n", getpid());
   printf("Hit enter to continue ");
   getchar(); /* wait for enter key */
   printf("Executing /usr/bin/less...\n");
   /* execute less using execl and error check it */
   if ( execl("/usr/bin/less", "less", 
      "/etc/passwd", (char*)NULL) == -1 )
   {
      perror("Can't execute program");
      return 1;
   }
   return 0;
}
```

1.  使用 Make 编译程序：

```
$> make execdemo
gcc -Wall -Wextra -pedantic -std=c99    execdemo.c   -o execdemo
```

1.  现在，在*当前*终端中运行程序：

```
$> ./execdemo
My PID is 920
Hit enter to continue
```

1.  现在，启动一个*新*终端，并使用`execdemo`的 PID 执行`pstree`：

```
$> pstree -A -p -s 920
systemd(1)---tmux(4050)---bash(18817)---execdemo(920)
```

1.  现在，回到运行`execdemo`的第一个终端，并按*Enter*。这将使用`less`打印密码文件。

1.  最后，回到第二个终端——您运行`pstree`的终端。重新运行相同的`pstree`命令。请注意，即使 PID 仍然相同，`execdemo`已被替换为`less`：

```
$> pstree -A -p -s 920
systemd(1)---tmux(4050)---bash(18817)---less(920)
```

## 它是如何工作的…

`execl()`函数执行一个新程序，并在同一个进程中替换旧程序。为了让程序暂停执行，以便我们有时间在`pstree`中查看它，我们使用了`getchar()`。

`execl()`函数有四个必需的参数。第一个是我们想要执行的程序的路径。第二个参数是程序的名称，就像从`argv[0]`中打印出来的那样。最后，第三个和之后的参数是我们想要传递给即将执行的程序的参数。为了*终止*我们想要传递给程序的参数列表，我们必须以`NULL`的指针结束，并将其转换为`char`类型。

另一种看待一个进程的方式是把它看作一个执行环境。在这个环境中运行的程序可以被替换。这就是为什么我们谈论进程，为什么我们称它们为*Process IDs*，而不是 Program IDs。

## 另请参阅

还有其他几个`exec()`函数可以使用，每个函数都有自己独特的特性和特点。这些通常被称为"`exec()` family"。你可以使用`man 3 execl`命令来了解它们的所有信息。

# fork 一个进程

之前，我们一直在说当一个程序创建一个新的进程时使用*spawned*。正确的术语是**fork**一个进程。发生的情况是一个进程创建了自己的一个副本——它*forks*。

在之前的教程中，我们学习了如何使用`execl()`在一个进程中执行一个新程序。在这个教程中，我们将学习如何使用`fork()`来 fork 一个进程。被 fork 的进程——子进程——是调用进程——父进程——的一个副本。

知道如何 fork 一个进程使我们能够在系统中以编程方式创建新的进程。如果不能 fork，我们只能限制在一个进程中。例如，如果我们想要从一个现有的程序中启动一个新程序并保留原始程序，我们必须 fork。

## 准备工作

就像在之前的教程中一样，你需要`pstree`工具。*技术要求*部分介绍了如何安装它。你还需要 GCC 编译器和 Make 工具。你还需要两个终端；一个终端用来执行程序，另一个用来用`pstree`查看进程树。

## 如何做...

在这个教程中，我们将使用`fork()`来 fork 一个进程。我们还将查看一个进程树，以便我们可以看到发生了什么。让我们开始吧：

1.  在一个程序中写下以下代码并保存为`forkdemo.c`。这段代码中突出显示了`fork()`系统调用。在我们`fork()`之前，我们打印出进程的 PID：

```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
   pid_t pid;
   printf("My PID is %d\n", getpid());
   /* fork, save the PID, and check for errors */
   if ( (pid = fork()) == -1 )
   { 
      perror("Can't fork");
      return 1;
   }
   if (pid == 0)
   {
      /* if pid is 0 we are in the child process */
      printf("Hello from the child process!\n");
      sleep(120);
   }

   else if(pid > 0)
   {
      /* if pid is greater than 0 we are in 
       * the parent */
      printf("Hello from the parent process! "
         "My child has PID %d\n", pid);
      sleep(120);
   }
   else
   {
      fprintf(stderr, "Something went wrong "
         "forking\n");
      return 1;
   }
   return 0;
}
```

1.  现在，编译程序：

```
$> make forkdemo
gcc -Wall -Wextra -pedantic -std=c99    forkdemo.c   
-o forkdemo
```

1.  在你*当前*的终端中运行程序并注意 PID：

```
$> ./forkdemo 
My PID is 21764
Hello from the parent process! My child has PID 21765
Hello from the child process!
```

1.  现在，在一个新的终端中，用`forkdemo`的 PID 运行`pstree`。在这里，我们可以看到`forkdemo`已经 fork 了，而我们在 fork 之前从程序中得到的 PID 是父进程。fork 的进程是正在运行的`forkdemo`：

```
$> pstree -A -p -s 21764
systemd(1)---tmux(4050)---bash(18817)---
forkdemo(21764)---forkdemo(21765)
```

## 它是如何工作的...

当一个进程 fork 时，它创建了自己的一个副本。这个副本成为调用`fork()`的进程的子进程——`fork()`返回子进程的 PID。在子进程中，返回`0`。这就是为什么父进程可以打印出子进程的 PID。

两个进程包含相同的程序代码，两个进程都在运行，但只有`if`语句中的特定部分会被执行，这取决于进程是父进程还是子进程。

## 还有更多...

一般来说，父进程和子进程是相同的，除了 PID。然而，还有一些其他的差异；例如，子进程中的 CPU 计数器会被重置。还有其他一些微小的差异，你可以在`man 2 fork`中了解到。然而，整个程序代码是相同的。

# 在一个 forked 进程中执行一个新程序

在上一个示例中，我们学习了如何使用`fork()`系统调用分叉进程。在之前的示例中，我们学习了如何用`execl()`替换进程中的程序。在这个示例中，我们将结合这两个，`fork()`和`execl()`，在一个分叉的进程中执行一个新程序。这就是每次在 Bash 中运行程序时发生的事情。Bash 分叉自身并执行我们输入的程序。

了解如何使用`fork()`和`execl()`使您能够编写启动新程序的程序。例如，您可以使用这些知识编写自己的 shell。

## 准备工作

对于这个示例，您需要`pstree`工具、GCC 编译器和 Make 工具。您可以在本章的*技术要求*部分找到这些程序的安装说明。

## 操作步骤…

在这个示例中，我们将编写一个程序，`fork()`并在子进程中执行一个新程序。让我们开始吧：

1.  在文件中写入以下程序代码，并将其保存为`my-fork.c`。当我们在子进程中执行一个新程序时，我们应该等待子进程完成。这就是我们使用`waitpid()`的方式。`waitpid()`调用还有另一个重要的功能，即从子进程获取返回状态：

```
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <sys/wait.h>
int main(void)
{
   pid_t pid;
   int status;
   /* Get and print my own pid, then fork
      and check for errors */
   printf("My PID is %d\n", getpid());
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   if (pid == 0)
   {
      /* If pid is 0 we are in the child process,
         from here we execute 'man ls' */
      if ( execl("/usr/bin/man", "man", "ls",
         (char*)NULL) == -1 )
      {
         perror("Can't exec");
         return 1;
      }
   }
   else if(pid > 0)
   {
      /* In the parent we must wait for the child
         to exit with waitpid(). Afterward, the
         child exit status is written to 'status' */
      waitpid(pid, &status, 0);
      printf("Child executed with PID %d\n", pid);
      printf("Its return status was %d\n", status);
      printf("Its return status was %d\n", status);
   }
   else
   {
      fprintf(stderr, "Something went wrong "
         "forking\n");
      return 1;
   }
   return 0;
}
```

1.  使用 Make 编译程序：

```
$> make my-fork
gcc -Wall -Wextra -pedantic -std=c99    my-fork.c   -o
my-fork
```

1.  在当前的终端中，找到当前 shell 的 PID 并做个记录：

```
$> echo $$
18817
```

1.  现在，使用`./my-fork`执行我们编译的程序。这将显示`ls`的手册页。

1.  打开一个新的终端，查看另一个终端中 shell 的进程树。注意，`my-fork`已经分叉并用`man`替换了其内容，`man`又分叉并用`pager`替换了其内容（以显示内容）：

```
$> pstree -A -p -s 18817
systemd(1)---tmux(4050)---bash(18817)---my-fork(5849)-
--man(5850)---pager(5861)
```

1.  通过按下*Q*退出第一个终端中的手册页。这将产生以下文本。比较`pstree`中父进程和子进程的 PID。注意子进程是`5850`，这是`man`命令。它最初是`my-fork`的副本，但后来用`man`替换了其程序：

```
My PID is 5849
Child executed with PID 5850
Its return status was 0
```

## 它是如何工作的…

`fork()`系统调用负责在 Linux 和 Unix 系统上分叉进程。然后，`execl()`（或其他`exec()`函数之一）负责执行并用新程序替换自己的程序。这基本上是系统上任何程序启动的方式。

请注意，我们需要告诉父进程使用`waitpid()`等待子进程。如果我们需要运行一个不需要终端的程序，我们可以不使用`waitpid()`。但是，我们应该始终等待子进程。如果不等待，子进程将最终成为**孤儿**。这是我们将在本章后面详细讨论的内容，在*学习孤儿是什么*这个示例中。

但在这种特殊情况下，我们执行需要终端的`man`命令，我们需要等待子进程才能让一切正常工作。`waitpid()`调用还使我们能够获取子进程的*返回状态*。我们还防止子进程变成孤儿。

当我们运行程序并用`pstree`查看进程树时，我们发现`my-fork`进程已经分叉并用`man`替换了其程序。我们可以看到这一点，因为`man`命令的 PID 与`my-fork`的子进程的 PID 相同。我们还注意到`man`命令反过来又分叉并用`pager`替换了其子进程。`pager`命令负责在屏幕上显示实际文本，通常是`less`。

# 使用 system()启动一个新进程

我们刚刚讨论的使用`fork()`、`waitpid()`和`execl()`在分叉的进程中启动新程序的内容是理解 Linux 和进程更深层次的关键。这种理解是成为优秀系统开发人员的关键。但是，有一个捷径。我们可以使用`system()`来代替手动处理分叉、等待和执行。`system()`函数为我们完成所有这些步骤。

## 准备工作

对于这个示例，你只需要本章节*技术要求*部分中列出的内容。

## 如何做…

在这个示例中，我们将使用`system()`函数重写前一个程序`my-fork`。你会注意到这个程序与前一个程序相比要短得多。让我们开始吧：

1.  将以下代码写入文件并保存为`sysdemo.c`。注意这个程序有多小（和简单）。`system()`函数为我们完成了所有复杂的工作：

```
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
   if ( (system("man ls")) == -1 )
   {
      fprintf(stderr, "Error forking or reading "
         "status\n");
      return 1;
   }
   return 0;
}
```

1.  编译程序：

```
$> make sysdemo
gcc -Wall -Wextra -pedantic -std=c99    sysdemo.c   -o
sysdemo
```

1.  使用`$$`变量记录 shell 的 PID：

```
$> echo $$
957
```

1.  现在在当前终端中运行程序。这将显示`ls`命令的手册页。让它继续运行：

```
$> ./sysdemo
```

1.  在新终端中启动并对*步骤 3*中的 PID 执行`pstree`。请注意，这里有一个额外的名为`sh`的进程。这是因为`system()`函数从`sh`（基本的 Bourne Shell）执行`man`命令：

```
$> pstree -A -p -s 957
systemd(1)---tmux(4050)---bash(957)---sysdemo(28274)--
-sh(28275)---man(28276)---pager(28287)
```

## 它是如何工作的…

这个程序要小得多，编写起来也更容易。然而，正如我们在`pstree`中看到的那样，与上一个示例相比，有一个额外的进程：`sh`（shell）。`system()`函数通过从`sh`执行`man`命令来工作。手册页（`man 3 system`）清楚地说明了这一点。它通过以下`execl()`调用执行我们指定的命令：

```
execl("/bin/sh", "sh", "-c", command, (char *) 0);
```

结果是一样的。它执行`fork()`，然后是`execl()`调用，并且使用`waitpid()`等待子进程。这也是一个使用低级系统调用的高级函数的很好的例子。

# 创建一个僵尸进程

要完全理解 Linux 中的进程，我们还需要看看什么是僵尸进程。为了完全理解这一点，我们需要自己创建一个。

**僵尸**进程是指子进程在父进程之前退出，而父进程没有等待子进程的状态。"僵尸进程"这个名字来源于这个事实，即进程是*不死的*。进程已经退出，但在系统进程表中仍然有一个条目。

了解什么是僵尸进程以及它是如何创建的将有助于你避免编写在系统上创建僵尸进程的糟糕程序。

## 准备工作

对于这个示例，你只需要本章节*技术要求*部分中列出的内容。

## 如何做…

在这个示例中，我们将编写一个小程序，在系统上创建一个僵尸进程。我们还将使用`ps`命令查看僵尸进程。为了证明我们可以通过等待子进程来避免僵尸进程，我们还将使用`waitpid()`编写第二个版本。让我们开始吧：

1.  将以下代码写入文件并命名为`create-zombie.c`。这个程序与我们在`forkdemo.c`文件中看到的程序相同，只是子进程在父进程退出之前使用`exit(0)`退出。父进程在子进程退出后睡眠 2 分钟，而不等待子进程使用`waitpid()`，从而创建一个僵尸进程。这里突出显示了`exit()`的调用：

```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(void)
{
   pid_t pid;
   printf("My PID is %d\n", getpid());
   /* fork, save the PID, and check for errors */
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   if (pid == 0)
   {
      /* if pid is 0 we are in the child process */
      printf("Hello and goodbye from the child!\n");
      exit(0);
      /* if pid is greater than 0 we are in 
       * the parent */
      printf("Hello from the parent process! "
         "My child had PID %d\n", pid);
      sleep(120);
   }
   else 
   {
      fprintf(stderr, "Something went wrong "
         "forking\n");
      return 1;
   }
   return 0;
}
```

1.  编译程序：

```
$> make create-zombie
gcc -Wall -Wextra -pedantic -std=c99    create-
zombie.c   -o create-zombie
```

1.  在当前终端中运行程序。程序（父进程）将保持活动状态 2 分钟。与此同时，子进程是僵尸的，因为父进程没有等待它或它的状态：

```
$> ./create-zombie
My PID is 2429
Hello from the parent process! My child had PID 2430
Hello and goodbye from the child!
```

1.  当程序正在运行时，打开另一个终端并使用`ps`检查子进程的 PID。你可以从`create-zombie`之前的输出中得到子进程的 PID。在这里，我们可以看到进程是僵尸的，因为它的状态是`Z+`，并且在进程名后面有`<defunct>`这个词：

```
$> ps a | grep 2430
  2430 pts/18   Z+     0:00 [create-zombie] <defunct>
  2824 pts/34   S+     0:00 grep 2430
```

1.  2 分钟后——当父进程执行完毕时——使用相同的 PID 重新运行`ps`命令。僵尸进程现在将不复存在：

```
$> ps a | grep 2430
  3364 pts/34   S+     0:00 grep 2430
```

1.  现在，重写程序，使其如下所示。将新版本命名为`no-zombie.c`。这里突出显示了添加的代码：

```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
int main(void)
{
   pid_t pid;
   int status;
   printf("My PID is %d\n", getpid());
   /* fork, save the PID, and check for errors */
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   if (pid == 0)
   {
      /* if pid is 0 we are in the child process */
      printf("Hello and goodbye from the child!\n");
      exit(0);
   }
   else if(pid > 0)
   {
      /* if pid is greater than 0 we are in 
       * the parent */
      printf("Hello from the parent process! "
         "My child had PID %d\n", pid);
      waitpid(pid, &status, 0); /* wait for child */
      sleep(120);
   }
   else
   {
      fprintf(stderr, "Something went wrong "
         "forking\n");
      return 1;
   }
   return 0;
}
```

1.  编译这个新版本：

```
$> make no-zombie
gcc -Wall -Wextra -pedantic -std=c99    no-zombie.c  
-o no-zombie
```

1.  在当前终端中运行程序。就像以前一样，它将创建一个子进程，该子进程将立即退出。父进程将继续运行 2 分钟，给我们足够的时间来搜索子进程的 PID：

```
$> ./no-zombie
My PID is 22101
Hello from the parent process! My child had PID 22102
Hello and goodbye from the child!
```

1.  当`no-zombie`程序正在运行时，在新的终端中使用`ps`和`grep`搜索子进程的 PID。正如你所看到的，没有与子进程的 PID 匹配的进程。因此，由于父进程等待其状态，子进程已正确退出：

```
$> ps a | grep 22102
22221 pts/34   S+     0:00 grep 22102
```

## 工作原理…

我们始终希望避免在系统上创建僵尸进程，而最好的方法是等待子进程完成。

在*步骤 1 到 5*中，我们编写了一个创建僵尸进程的程序。由于父进程没有使用`waitpid()`系统调用等待子进程，因此创建了僵尸进程。子进程确实退出了，但它仍然留在系统进程表中。当我们使用`ps`和`grep`搜索进程时，我们看到子进程的状态为`Z+`，表示僵尸。该进程不存在，因为它已经使用`exit()`系统调用退出。但是，根据系统进程表，它仍然存在；因此，它是不死不活的—一个僵尸。

在*步骤 6 到 9*中，我们使用`waitpid()`系统调用重写了程序以等待子进程。子进程仍然在父进程之前存在，但这次父进程获得了子进程的状态。

僵尸进程不会占用任何系统资源，因为进程已经终止。它只驻留在系统进程表中。但是，系统上的每个进程—包括僵尸进程—都占用一个 PID 号。由于系统可用的 PID 号是有限的，如果死进程占用 PID 号，就有耗尽 PID 号的风险。

## 还有更多…

在 Linux 的`waitpid()`手册页中有关于子进程及其状态变化的许多细节。实际上，在 Linux 中有三个可用的`wait()`函数。你可以使用`man 2 wait`命令阅读有关它们的所有内容。

# 了解孤儿的含义

了解 Linux 系统中孤儿的含义就像了解僵尸一样重要。这将使你更深入地了解整个系统以及进程如何被`systemd`继承。

一个`systemd`，它是系统上的第一个进程—PID 为`1`。

在本食谱中，我们将编写一个小程序，该程序分叉，从而创建一个子进程。然后父进程将退出，将子进程留下来作为孤儿。

## 准备就绪

本章的*技术要求*部分列出了本食谱所需的一切。

## 如何做…

在本食谱中，我们将编写一个创建孤儿进程的简短程序，该进程将由`systemd`继承。让我们开始吧：

1.  在文件中编写以下代码并将其保存为`orphan.c`。该程序将创建一个在后台运行 5 分钟的子进程。当我们按下*Enter*时，父进程将退出。这给了我们时间在父进程退出之前和之后使用`pstree`调查子进程：

```
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
int main(void)
{
   pid_t pid;
   printf("Parent PID is %d\n", getpid());
   /* fork, save the PID, and check for errors */
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   if (pid == 0)
   {
      /* if pid is 0 we are in the child process */
      printf("I am the child and will run for "
         "5 minutes\n");
      sleep(300);
      exit(0);
   }
   else if(pid > 0)
   {
      /* if pid is greater than 0 we are in 
       * the parent */
      printf("My child has PID %d\n" 
         "I, the parent, will exit when you "
         "press enter\n", pid);
      getchar();
      return 0;
   }
   else
   {
      fprintf(stderr, "Something went wrong "
         "forking\n");
      return 1;
   }
   return 0;
}
```

1.  编译此程序：

```
$> make orphan
gcc -Wall -Wextra -pedantic -std=c99    orphan.c   -o
 orphan
```

1.  在当前终端中运行程序并让程序继续运行。暂时不要按*Enter*：

```
$> ./orphan
My PID is 13893
My child has PID 13894
I, the parent, will exit when you press enter
I am the child and will run for 2 minutes
```

1.  现在，在一个新的终端中，使用子进程的 PID 运行`pstree`。在这里，我们将看到它看起来就像在之前的食谱中一样。进程已经被分叉，从而创建了一个具有相同内容的子进程：

```
$> pstree -A -p -s 13894
systemd(1)---tmux(4050)---bash(18817)---orphan(13893)-
--orphan(13894)
```

1.  现在，是时候结束父进程了。回到`orphan`仍在运行的终端并按下*Enter*。这将结束父进程。

1.  现在，在第二个终端中再次运行`pstree`。这与刚刚运行的命令相同。正如你所看到的，子进程现在已被`systemd`继承，因为其父进程已经死亡。5 分钟后，子进程将退出：

```
$> pstree -A -p -s 13894
systemd(1)---orphan(13894)
```

1.  我们可以使用其他更标准化的工具来查看`ps`。运行以下`ps`命令以查看有关子进程的更详细信息。在这里，我们将看到更多信息。对我们来说最重要的是 PPID、PID 和**会话 ID**（**SID**）。我们还将在这里看到**用户 ID**（**UID**），它指定了谁拥有该进程：

```
$> ps jp 13894
PPID PID PGID  SID   TTY  TPGID STAT UID TIME COMMAND
1  13894 13893 18817 pts/18 18817 S 1000 0:00 ./orphan
```

## 工作原理…

每个进程都需要一个父进程。这就是为什么`systemd`会继承系统上任何成为孤儿的进程的原因。

`if (pid == 0)`中的代码继续运行了 5 分钟。这给了我们足够的时间来检查子进程是否已被`systemd`继承。

在最后一步，我们使用`ps`查看了有关子进程的更多详细信息。在这里，我们看到了 PPID、PID、PGID 和 SID。这里提到了一些重要的新名称。我们已经知道 PPID 和 PID，但 PGID 和 SID 还没有被介绍过。

**PGID**代表**进程组 ID**，是系统对进程进行分组的一种方式。子进程的 PGID 是父进程的 PID。换句话说，这个 PGID 是为了将父进程和子进程分组在一起而创建的。系统将 PGID 设置为创建该组的父进程的 PID。我们不需要自己创建这些组；这是系统为我们做的事情。

`18817`，这是 Bash shell 的 PID。这里也适用相同的规则；SID 号将与启动会话的进程的 PID 相同。这个会话包括我的用户 shell 和我从中启动的所有程序。这样，系统就可以在我注销系统时终止属于该会话的所有进程。

## 另请参阅

使用`ps`可以获得很多信息。我建议你至少浏览一下`man 1 ps`的手册。

# 创建守护进程

在系统编程中常见的任务是创建各种守护进程。**守护进程**是在系统上运行并执行一些任务的后台进程。SSH 守护进程就是一个很好的例子。另一个很好的例子是 NTP 守护进程，它负责同步计算机时钟，有时甚至分发时间给其他计算机。

了解如何创建守护进程将使您能够创建服务器软件；例如，Web 服务器、聊天服务器等。

在本教程中，我们将创建一个简单的守护进程来演示一些重要的概念。

## 准备工作

你只需要本章节*技术要求*部分列出的组件。

## 操作方法

在本教程中，我们将编写一个在我们的系统中后台运行的小型守护进程。守护进程唯一的“工作”是将当前日期和时间写入文件。这证明了守护进程是活着的。让我们开始吧：

1.  与我们以前的示例相比，守护进程的代码相当长。因此，代码已分成几个步骤。这里还有一些我们还没有涉及的新东西。将代码写入一个文件并将其保存为`my-daemon.c`。请记住，所有步骤中的所有代码都放入这个文件中。我们将从我们需要的所有`include`文件、我们需要的变量和我们的`fork()`开始，就像我们以前看到的那样。这个`fork()`将是两个中的第一个：

```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
int main(void)
{
   pid_t pid;
   FILE *fp;
   time_t now; /* for the current time */
   const char pidfile[] = "/var/run/my-daemon.pid";
   const char daemonfile[] = 
      "/tmp/my-daemon-is-alive.txt";
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
```

1.  现在我们已经 forked，我们希望父进程退出。一旦父进程退出，我们将处于子进程中。在子进程中，我们将使用`setsid()`创建一个新的会话。创建一个新的会话将释放进程的控制终端：

```
   else if ( (pid != 0) )
   {
      exit(0);
   }
   /* the parent process has exited, so this is the
    * child. create a new session to lose the 
    * controlling terminal */
   setsid();
```

1.  现在，我们想再次`fork()`。这第二次 fork 将创建一个新的进程，就像以前一样，但由于它是一个已经存在的会话中的新进程，它不会成为会话领导者，从而阻止它获取一个新的控制终端。新的子进程被称为孙子。再一次，我们退出父进程（子进程）。然而，在退出子进程之前，我们将孙子的 PID 写入**PID 文件**。这个 PID 文件用于跟踪守护进程：

```
   /* fork again, creating a grandchild, 
    * the actual daemon */
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   /* the child process which will exit */
   else if ( pid > 0 )
   {
      /* open pid-file for writing and error 
       * check it */
      if ( (fp = fopen(pidfile, "w")) == NULL )
      {
         perror("Can't open file for writing");
         return 1;
      }
      /* write pid to file */
      fprintf(fp, "%d\n", pid); 
      fclose(fp); /* close the file pointer */
      exit(0);
   }
```

1.  现在，将默认模式（*umask*）设置为守护进程的合理值。我们还必须将当前工作目录更改为`/`，以便守护进程不会阻止文件系统卸载或目录被删除。然后，我们必须打开守护进程文件，这是我们将写入消息的地方。消息将包含当前日期和时间，并告诉我们一切是否正常。通常，这将是一个日志文件：

```
   umask(022); /* set the umask to something ok */
   chdir("/"); /* change working directory to / */
   /* open the "daemonfile" for writing */
   if ( (fp = fopen(daemonfile, "w")) == NULL )
   {
      perror("Can't open daemonfile");
      return 1;
   }
```

1.  由于守护进程只会在后台运行，我们不需要 stdin、stdout 和 stderr，所以让我们将它们全部关闭。但是，将它们关闭是不安全的。如果代码中的某些部分稍后打开文件描述符，它将获得文件描述符 0，通常是 stdin。文件描述符是按顺序分配的。如果没有打开的文件描述符，第一次调用`open()`将获得描述符`0`；第二次调用将获得描述符`1`。另一个问题可能是，某些部分可能尝试写入 stdout，但 stdout 已经不存在，这会导致程序崩溃。因此，我们必须重新打开它们全部，但是重新打开到`/dev/null`（黑洞）：

```
   /* from here, we don't need stdin, stdout or, 
    * stderr anymore, so let's close them all, 
    * then re-open them to /dev/null */
   close(STDIN_FILENO);
   close(STDOUT_FILENO);
   close(STDERR_FILENO);
   open("/dev/null", O_RDONLY); /* 0 = stdin */
   open("/dev/null", O_WRONLY); /* 1 = stdout */
   open("/dev/null", O_RDWR); /* 2 = stderr */
```

1.  最后，我们可以开始守护进程的工作。这只是一个`for`循环，向守护进程文件写入一条消息，说明守护进程仍然存活。请注意，我们必须在每次`fprintf()`后使用`fflush()`刷新文件指针。通常，在 Linux 中，事情是*行缓冲*的，这意味着在写入之前只缓冲一行。但由于这是一个文件而不是 stdout，它实际上是完全缓冲的，这意味着它会缓冲所有数据，直到缓冲区满或文件流关闭。如果没有`fflush()`，我们在填满缓冲区之前将看不到文件中的任何文本。通过在每次`fprintf()`后使用`fflush()`，我们可以在文件中实时看到文本：

```
   /* here we start the daemons "work" */
   for (;;)
   {
      /* get the current time and write it to the
         "daemonfile" that we opened above */
      time(&now);
      fprintf(fp, "Daemon alive at %s", 
         ctime(&now));
      fflush(fp); /* flush the stream */
      sleep(30);
   }
   return 0;
}
```

1.  现在，是时候编译整个守护进程了：

```
$> make my-daemon
gcc -Wall -Wextra -pedantic -std=c99    my-daemon.c  
-o my-daemon
```

1.  现在，我们可以启动守护进程。由于我们将 PID 文件写入`/var/run`，我们需要以 root 身份执行守护进程。我们不会从守护进程中得到任何输出；它将悄悄地与终端分离：

```
$> sudo ./my-daemon
```

1.  现在守护进程正在运行，让我们检查已写入`/var/run/my-daemon.pid`的 PID 号码：

```
$> cat /var/run/my-daemon.pid 
5508
```

1.  让我们使用`ps`和`pstree`来调查守护进程。如果一切都按照预期进行，它的父进程应该是`systemd`，并且它应该在自己的会话中（SID 应该与进程 ID 相同）：

```
$> ps jp 5508
PPID PID PGID SID TTY TPGID STAT UID TIME COMMAND
1   5508 5508 5508?   -1    Ss    0  0:00 ./my-daemon
$> pstree -A -p -s 5508
systemd(1)---my-daemon(5508)
```

1.  让我们还看看`/tmp/my-daemon-is-alive.txt`文件。这个文件应该包含一些指定日期和时间的行，相隔 30 秒：

```
$> cat /tmp/my-daemon-is-alive.txt 
Daemon alive at Sun Nov 22 23:25:45 2020
Daemon alive at Sun Nov 22 23:26:15 2020
Daemon alive at Sun Nov 22 23:26:45 2020
Daemon alive at Sun Nov 22 23:27:15 2020
Daemon alive at Sun Nov 22 23:27:45 2020
Daemon alive at Sun Nov 22 23:28:15 2020
Daemon alive at Sun Nov 22 23:28:45 2020
```

1.  最后，让我们杀死守护进程，以防止它继续写入文件：

```
$> sudo kill 5508
```

## 工作原理…

我们刚刚编写的守护进程是一个基本的传统守护进程，但它演示了我们需要充分理解的所有概念。其中一个新的重要概念是如何使用`setsid()`启动一个新会话。如果我们不创建一个新会话，守护进程仍将是用户登录会话的一部分，并在用户注销时终止。但由于我们为守护进程创建了一个新会话，并且它被`systemd`继承，它现在独立存在，不受启动它的用户和进程的影响。

第二次分叉的原因是，会话领导者——也就是我们在`setsid()`调用后的第一个子进程——如果打开终端设备，可以获取一个新的控制终端。当我们进行第二次分叉时，新的子进程只是第一个子进程创建的会话的成员，而不是领导者，因此它不再能获取**控制终端**。避免控制终端的原因是，如果该终端退出，守护进程也会退出。在创建守护进程时进行两次分叉通常被称为**双重分叉**技术。

需要以 root 身份启动守护进程的原因是它需要写入`/var/run/`。如果我们改变目录，或者完全跳过它，守护进程将作为普通用户正常运行。然而，大多数守护进程确实以 root 身份运行。然而，也有一些以普通用户身份运行的守护进程；例如，处理与用户相关的事务的守护进程，比如`tmux`（一个终端复用器）。

我们还将工作目录更改为`/`。这样守护进程就不会锁定目录。顶级根目录不会被删除或卸载，这使其成为守护进程的安全工作目录。

## 还有更多...

我们在这里编写的是传统的 Linux/Unix 守护进程。这些类型的守护进程今天仍在使用，例如，用于像这样的小型和快速守护进程。然而，自从`systemd`出现以来，我们不再需要像刚才那样“使守护进程成为守护进程”。例如，建议保留 stdout 和 stderr 打开，并将所有日志消息发送到那里。然后这些消息将显示在*journal*中。我们将在*第七章**，使用 systemd 处理您的守护进程*中更深入地介绍 systemd 和 journal。

我们在这里编写的守护进程类型在 systemd 语言中被称为*forking*，我们以后会更多地了解它。

就像`system()`在执行新程序时为我们简化了事情一样，还有一个名为`daemon()`的函数可以为我们创建守护进程。这个函数将为我们做所有繁重的工作，比如分叉、关闭和重新打开文件描述符、更改工作目录等。然而，请注意，这个函数不使用我们在本篇中用于守护进程的双重分叉技术。这一事实在`man 3 daemon`手册页的 BUGS 部分中明确说明。

# 实现信号处理程序

在上一篇中，我们编写了一个简单但功能齐全的守护进程。然而，它也存在一些问题；例如，当守护进程被终止时，PID 文件没有被删除。同样，当守护进程被终止时，打开的文件流（`/tmp/my-daemon-is-alive.txt`）也没有被关闭。一个合适的守护进程在退出时应该进行清理。

为了能够在退出时进行清理，我们需要实现一个信号处理程序。然后信号处理程序应该在守护进程终止之前处理所有的清理工作。在本章中，我们已经看到了信号处理程序的例子，所以这个概念并不新鲜。

然而，并不只有守护进程使用信号处理程序。这是一种常见的控制进程的方式，特别是那些没有控制终端的进程。

## 准备工作

在阅读本篇之前，您应该先阅读上一篇，以便了解守护进程的功能。除此之外，您还需要本章*技术要求*部分列出的程序。

## 操作方法

在本篇中，我们将为上一篇中编写的守护进程添加信号处理程序。由于代码会有点长，我将其分成几个步骤。不过，请记住，所有的代码都在同一个文件中。让我们开始吧：

1.  将以下代码写入文件并命名为`my-daemon-v2.c`。我们将从`#include`文件和变量开始，就像之前一样。但是请注意，这一次我们已经将一些变量移到了全局空间。我们这样做是为了让信号处理程序可以访问它们。没有办法向信号处理程序传递额外的参数，所以这是访问它们的最佳方式。在这里，我们还必须为`sigaction()`定义`_POSIX_C_SOURCE`。我们还必须在这里创建我们的信号处理程序的原型，称为`sigHandler()`。另外，请注意新的`sigaction`结构：

```
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
void sigHandler(int sig);
/* moved these variables to the global scope
   since they need to be access/deleted/closed
   from the signal handler */
FILE *fp;
const char pidfile[] = "/var/run/my-daemon.pid";
int main(void)
{
   pid_t pid;
   time_t now; /* for the current time */
   struct sigaction action; /* for sigaction */
   const char daemonfile[] = 
      "/tmp/my-daemon-is-alive.txt";
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   else if ( (pid != 0) )
   {
      exit(0);
   }
```

1.  就像之前一样，我们必须在第一次分叉后创建一个新会话。之后，我们必须进行第二次分叉，以确保它不再是一个会话领导者：

```
   /* the parent process has exited, which makes 
    * the rest of the code the child process */
   setsid(); /* create a new session to lose the 
                controlling terminal */

   /* fork again, creating a grandchild, the 
    * actual daemon */
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   /* the child process which will exit */
   else if ( pid > 0 )
   {
      /* open pid-file for writing and check it */
      if ( (fp = fopen(pidfile, "w")) == NULL )
      {
         perror("Can't open file for writing");
         return 1;
      }
      /* write pid to file */
      fprintf(fp, "%d\n", pid); 
      fclose(fp); /* close the file pointer */
      exit(0);
   }
```

1.  与之前一样，我们必须更改 umask、当前工作目录，并使用`fopen()`打开守护进程文件。接下来，我们必须关闭并重新打开 stdin、stdout 和 stderr：

```
   umask(022); /* set the umask to something ok */
   chdir("/"); /* change working directory to / */
   /* open the "daemonfile" for writing */
   if ( (fp = fopen(daemonfile, "w")) == NULL )
   {
      perror("Can't open daemonfile");
      return 1;
   }
   /* from here, we don't need stdin, stdout or, 
    * stderr anymore, so let's close them all, 
    * then re-open them to /dev/null */
   close(STDIN_FILENO);
   close(STDOUT_FILENO);
   close(STDERR_FILENO);
   open("/dev/null", O_RDONLY); /* 0 = stdin */
   open("/dev/null", O_WRONLY); /* 1 = stdout */
   open("/dev/null", O_RDWR); /* 2 = stderr */
```

1.  现在，终于是时候准备并注册信号处理程序了。这正是我们在本章前面讨论过的内容，只是在这里，我们为所有常见的退出信号注册处理程序，比如终止、中断、退出和中止。一旦我们处理了信号处理程序，我们将开始守护进程的工作；也就是，将消息写入守护进程文件的`for`循环：

```
/* prepare for sigaction */
   action.sa_handler = sigHandler;
   sigfillset(&action.sa_mask);
   action.sa_flags = SA_RESTART;
   /* register the signals we want to handle */
   sigaction(SIGTERM, &action, NULL);
   sigaction(SIGINT, &action, NULL);
   sigaction(SIGQUIT, &action, NULL);
   sigaction(SIGABRT, &action, NULL);
   /* here we start the daemons "work" */
   for (;;)
   {
      /* get the current time and write it to the
         "daemonfile" that we opened above */
      time(&now);
      fprintf(fp, "Daemon alive at %s", 
         ctime(&now));
      fflush(fp); /* flush the stream */
      sleep(30);
   }
   return 0;
}
```

1.  最后，我们必须实现信号处理程序的函数。在这里，我们通过在退出之前删除 PID 文件来清理守护进程。我们还关闭了打开的文件流到守护进程文件：

```
void sigHandler(int sig)
{
    int status = 0;
    if ( sig == SIGTERM || sig == SIGINT 
        || sig == SIGQUIT 
        || sig == SIGABRT )
    {
        /* remove the pid-file */
        if ( (unlink(pidfile)) == -1 )
            status = 1;
        if ( (fclose(fp)) == EOF )
            status = 1;
        exit(status); /* exit with the status set*/
    }
    else /* some other signal */
    {
        exit(1);
    }
}
```

1.  编译守护进程的新版本：

```
$> make my-daemon-v2
gcc -Wall -Wextra -pedantic -std=c99    my-daemon-v2.c
-o my-daemon-v2
```

1.  以 root 身份启动守护进程，就像我们之前做的那样：

```
$> sudo ./my-daemon-v2 
```

1.  查看 PID 文件中的 PID 并做好记录：

```
$> cat /var/run/my-daemon.pid 
22845
```

1.  使用`ps`命令查看它是否按预期运行：

```
$> ps jp 22845
  PPID   PID  PGID   SID TTY TPGID STAT UID TIME
COMMAND
    1 22845 22845 22845 ?      -1 Ss     0 0:00 ./my
daemon-v2
```

1.  用默认信号`TERM`杀死守护进程：

```
$> sudo kill 22845
```

1.  如果一切按计划进行，PID 文件将被删除。尝试使用`cat`命令访问 PID 文件：

```
$> cat /var/run/my-daemon.pid 
cat: /var/run/my-daemon.pid: No such file or directory
```

## 工作原理…

在这个示例中，我们实现了一个信号处理程序，负责所有清理工作。它会删除 PID 文件并关闭打开的文件流。为了处理最常见的“退出”信号，我们使用四个不同的信号注册了处理程序：*终止*、*中断*、*退出*和*中止*。当守护进程接收到其中一个信号时，它会触发`sigHandler()`函数。该函数然后会删除 PID 文件并关闭文件流。最后，该函数通过调用`exit()`退出整个守护进程。

然而，由于我们无法将文件名或文件流作为参数传递给信号处理程序，我们将这些变量放在全局范围内。这样一来，`main()`和`sigHandler()`都可以访问它们。

## 更多内容…

记得我们之前必须刷新流才能在`/tmp/my-daemon-is-alive.txt`中显示时间和日期吗？由于现在守护进程退出时关闭文件流，我们不再需要`fflush()`。数据在关闭时被写入文件。然而，这样一来，我们就无法在守护进程运行时“实时”看到时间和日期。这就是为什么我们在代码中仍然保留了`fflush()`。
