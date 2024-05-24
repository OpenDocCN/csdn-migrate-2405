# Go 系统编程（四）

> 原文：[`zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C`](https://zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：处理系统文件

在上一章中，我们讨论了在 Go 中的文件输入和输出，并创建了`wc(1)`、`dd(1)`和`cp(1)`实用程序的 Go 版本。

虽然本章的主要主题是 Unix 系统文件和日志文件，但你还将学到许多其他内容，包括模式匹配、文件权限、与用户和组的工作，以及在 Go 中处理日期和时间。对于所有这些主题，你将看到方便的 Go 代码，这些代码将解释所呈现的技术，并且可以在你自己的 Go 程序中使用，而不需要太多更改。

因此，本章将讨论以下主题：

+   向现有文件追加数据

+   读取文件并修改每一行

+   在 Go 中进行正则表达式和模式匹配

+   将信息发送到 Unix 日志文件

+   在 Go 中处理日期和时间

+   处理 Unix 文件权限

+   处理用户 ID 和组 ID

+   了解有关文件和目录的更多信息

+   处理日志文件并从中提取有用信息

+   使用随机数生成难以猜测的密码

# 哪些文件被视为系统文件？

每个 Unix 操作系统都包含负责系统配置和各种服务的文件。大多数这些文件位于`/etc`目录中。我也喜欢将日志文件视为系统文件，尽管有些人可能不同意。通常，大多数系统日志文件可以在`/var/log`目录中找到。然而，Apache 和 nginx web 服务器的日志文件可能会根据其配置而放在其他位置。

# 在 Go 中记录

`log`包提供了在 Unix 机器上记录信息的一般方法，而`log/syslog` Go 包允许你使用所需的日志级别和日志设施将信息发送到系统日志服务。此外，`time`包可以帮助你处理日期和时间。

# 将数据放在文件末尾

如第六章中所讨论的*文件输入和输出*，在本章中，我们将讨论如何在不破坏现有数据的情况下打开文件进行写入。

将演示技术的 Go 程序`appendData.go`将接受两个命令行参数：要追加的消息和将存储文本的文件名。这个程序将分为三部分呈现。

`appendData.go`的第一部分包含以下 Go 代码：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
) 
```

如预期的那样，程序的第一部分包含将在程序中使用的 Go 包。

第二部分如下：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) != 3 { 
         fmt.Printf("usage: %s message filename\n", filepath.Base(arguments[0])) 
         os.Exit(1) 
   } 
   message := arguments[1] 
   filename := arguments[2] 

   f, err := os.OpenFile(filename, 
os.O_RDWR|os.O_APPEND|os.O_CREATE, 0660) 
```

`os.OpenFile()`函数的`os.O_APPEND`标志告诉 Go 在文件末尾进行写入。此外，`os.O_CREATE`标志将使`os.OpenFile()`在文件不存在时创建文件，这非常方便，因为它可以避免你编写测试文件是否已存在的 Go 代码。

程序的最后一部分如下：

```go
   if err != nil { 
         fmt.Println(err) 
         os.Exit(-1) 
   } 
   defer f.Close() 

   fmt.Fprintf(f, "%s\n", message) 
} 
```

`fmt.Fprintf()`函数在这里用于将消息以纯文本形式写入文件。正如你所看到的，`appendData.go`是一个相对较小的 Go 程序，没有任何意外。

执行`appendData.go`不会产生输出，但它会完成它的工作，你可以从`appendData.go`执行前后的`cat(1)`实用程序的输出中看到这一点：

```go
$ cat test
[test]: test
: test
$ go run appendData.go test test
$ cat test
[test]: test
: test
test 
```

# 修改现有数据

本节将教你如何修改文件的内容。将开发的程序将完成一个非常方便的工作：在文本文件的每一行前添加行号。这意味着你需要逐行读取输入文件，保持一个变量来保存行号值，并使用原始名称保存它。此外，保存行号值的变量的初始值可以在启动程序时定义。Go 程序的名称将是`insertLineNumber.go`，它将分为四部分呈现。

首先，你会看到预期的序言：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "io/ioutil" 
   "os" 
   "strings" 
) 
```

第二部分主要是`flag`包的配置：

```go
func main() { 
   minusINIT := flag.Int("init", 1, "Initial Value") 
   flag.Parse() 
   flags := flag.Args() 

   if len(flags) == 0 { 
         fmt.Printf("usage: insertLineNumber <files>\n") 
         os.Exit(1) 
   } 

   lineNumber := *minusINIT
   for _, filename := range flags { 
         fmt.Println("Processing:", filename) 
```

`lineNumber`变量由`minusINIT`标志的值初始化。此外，该实用程序可以使用`for`循环处理多个文件。

程序的第三部分如下：

```go
         input, err := ioutil.ReadFile(filename) 
         if err != nil { 
               fmt.Println(err) 
               os.Exit(-1) 
         } 

         lines := strings.Split(string(input), "\n") 
```

正如您所看到的，`insertLineNumber.go`使用`ioutil.ReadFile()`一次性读取其输入文件，当处理大型文本文件时可能效率不高。但是，使用今天的计算机，这不应该是问题。更好的方法是逐行读取输入文件，将每个更改后的行写入临时文件，然后用临时文件替换原始文件。

实用程序的最后部分如下：

```go
         for i, line := range lines { 
               lines[i] = fmt.Sprintf("%d: %s ", lineNumber, line) 
               lineNumber = lineNumber + 1
         } 

         lines[len(lines)-1] = "" 
         output := strings.Join(lines, "\n") 
         err = ioutil.WriteFile(filename, []byte(output), 0644) 
         if err != nil { 
               fmt.Println(err) 
               os.Exit(-1) 
         } 
   } 
   fmt.Println("Processed", lineNumber-*minusINIT, "lines!") 
}
```

由于`range`循环会在文件末尾引入额外的一行，因此您必须使用`lines[len(lines)-1] = ""`语句删除行切片中的最后一行，这意味着程序假定它处理的所有文件都以换行符结尾。如果您的文本文件没有这样做，那么您可能需要更改`insertLineNumber.go`的代码或在文本文件末尾添加一个新行。

运行`insertLineNumber.go`除了处理的每个文件的文件名和处理的总行数之外，不会生成任何可见的输出。但是，您可以通过查看您处理的文件的内容来查看其执行的结果：

```go
$ cat test
a

b
$ go run insertLineNumber.go -init=10 test
Processing: test
Processed 4 lines!
$ cat test
10: a
11:
12: b
```

如果尝试多次处理相同的输入文件，如以下示例，将会发生有趣的事情：

```go
$ cat test
a

b
$ go run insertLineNumber.go -init=10 test test test
Processing: test
Processing: test
Processing: test
Processed 12 lines!
$ cat test
18: 14: 10: a
19: 15: 11:
20: 16: 12: b
```

# 关于日志文件

这部分将教您如何将信息从 Go 程序发送到日志服务，从而发送到系统日志文件。尽管保留信息很重要，但对于服务器进程来说，日志文件是必需的，因为服务器进程没有其他方式将信息发送到外部世界，因为它没有终端来发送任何输出。

日志文件很重要，您不应该低估其中存储的信息的价值。当 Unix 机器上发生奇怪的事情时，日志文件应该是寻求帮助的第一地方。

一般来说，使用日志文件比在屏幕上显示输出更好，原因有两个：首先，输出不会丢失，因为它存储在文件中；其次，您可以使用 Unix 工具（如`grep(1)`、`awk(1)`和`sed(1)`）搜索和处理日志文件，而在终端窗口上打印消息时无法做到这一点。

# 关于日志记录

所有 Unix 机器都有一个单独的服务器进程用于记录日志文件。在 macOS 机器上，该进程的名称是`syslogd(8)`。另一方面，大多数 Linux 机器使用`rsyslogd(8)`，这是`syslogd(8)`的改进和更可靠的版本，后者是用于消息记录的原始 Unix 系统实用程序。

然而，无论您使用的 Unix 变体是什么，或者用于记录日志的服务器进程的名称是什么，日志记录在每台 Unix 机器上的工作方式都是相同的，因此不会影响您将编写的 Go 代码。

观看一个或多个日志文件的最佳方法是使用`tail(1)`实用程序的帮助，后跟`-f`标志和您想要观看的日志文件的名称。`-f`标志告诉`tail(1)`等待额外的数据。您将需要通过按*Ctrl* + *C*来终止这样的`tail(1)`命令。

# 日志设施

日志设施就像用于记录信息的类别。日志设施部分的值可以是`auth`、`authpriv`、`cron`、`daemon`、`kern`、`lpr`、`mail`、`mark`、`news`、`syslog`、`user`、`UUCP`、`local0`、`local1`、`local2`、`local3`、`local4`、`local5`、`local6`和`local7`中的任何一个；这在`/etc/syslog.conf`、`/etc/rsyslog.conf`或其他适当的文件中定义，具体取决于您的 Unix 机器上用于系统日志记录的服务器进程。这意味着如果未定义和处理日志设施，则您发送到其中的日志消息可能会丢失。

# 日志级别

**日志级别**或**优先级**是指定日志条目严重性的值。存在各种日志级别，包括*debug*、*info*、*notice*、*warning*、*err*、*crit*、*alert*和*emerg*，按严重性的相反顺序。

查看 Linux 机器的`/etc/rsyslog.conf`文件，了解如何控制日志设施和日志级别。

# syslog Go 包

本小节将介绍一个在所有 Unix 机器上运行并以各种方式向日志服务发送数据的 Go 程序。程序的名称是`useSyslog.go`，将分为四个部分。

首先，您将看到预期的序言：

```go
package main 

import ( 
   "fmt" 
   "log" 
   "log/syslog" 
   "os" 
   "path/filepath" 
) 
```

您必须使用`log`包进行日志记录，使用`log/syslog`包定义程序的日志设施和日志级别。

第二部分如下：

```go
func main() { 
   programName := filepath.Base(os.Args[0]) 
   sysLog, e := syslog.New(syslog.LOG_INFO|syslog.LOG_LOCAL7, programName) 
   if e != nil { 
         log.Fatal(e) 
   } 
   sysLog.Crit("Crit: Logging in Go!") 
```

`syslog.New()`函数调用返回一个写入器，告诉您的程序将所有日志消息定向到何处。好消息是您已经知道如何使用写入器！

请注意，开发人员应定义程序使用的优先级和设施。

然而，即使有了定义的优先级和设施，`log/syslog`包也允许您使用诸如`sysLog.Crit()`之类的函数将直接日志消息发送到其他优先级。

程序的第三部分如下：

```go
   sysLog, e = syslog.New(syslog.LOG_ALERT|syslog.LOG_LOCAL7, "Some program!") 
   if e != nil { 
         log.Fatal(sysLog) 
   } 
sysLog.Emerg("Emerg: Logging in Go!") 
```

这部分显示您可以在同一个程序中多次调用`syslog.New()`。再次调用`Emerg()`函数允许您绕过`syslog.New()`函数定义的内容。

最后一部分如下：

```go
   fmt.Fprintf(sysLog, "log.Print: Logging in Go!") 
} 
```

这是唯一使用由`syslog.New()`定义的日志优先级和日志设施的调用，直接写入`sysLog`写入器。

执行`useLog.go`将在屏幕上生成一些输出，但也会将数据写入适当的日志文件。在 macOS Sierra 或 Mac OS X 机器上，您将看到以下内容：

```go
$ go run useSyslog.go

Broadcast Message from _iconservices@iMac.local
        (no tty) at 18:01 EEST...

Emerg: Logging in Go!
$ grep "Logging in Go" /var/log/* 2>/dev/null
/var/log/system.log:May 19 18:01:31 iMac useSyslog[22608]: Crit: Logging in Go!
/var/log/system.log:May 19 18:01:31 iMac Some program![22608]: Emerg: Logging in Go!
/var/log/system.log:May 19 18:01:31 iMac Some program![22608]: log.Print: Logging in Go!
```

在 Debian Linux 机器上，您将看到以下结果：

```go
$ go run useSyslog.go

Message from syslogd@mail at May 19 18:03:00 ...
Some program![1688]: Emerg: Logging in Go!
$
Broadcast message from systemd-journald@mail (Fri 2017-05-19 18:03:00 EEST):

useSyslog[1688]: Some program![1688]: Emerg: Logging in Go!
$ tail -5 /var/log/syslog
May 19 18:03:00 mail useSyslog[1688]: Crit: Logging in Go!
May 19 18:03:00 mail Some program![1688]: Emerg: Logging in Go!
May 19 18:03:00 mail Some program![1688]: log.Print: Logging in Go!
$ grep "Logging in Go" /var/log/* 2>/dev/null
/var/log/cisco.log:May 19 18:03:00 mail useSyslog[1688]: Crit: Logging in Go!
/var/log/cisco.log:May 19 18:03:00 mail Some program![1688]: Emerg: Logging in Go!
/var/log/cisco.log:May 19 18:03:00 mail Some program![1688]: log.Print: Logging in Go!
/var/log/syslog:May 19 18:03:00 mail useSyslog[1688]: Crit: Logging in Go!
/var/log/syslog:May 19 18:03:00 mail Some program![1688]: Emerg: Logging in Go!
/var/log/syslog:May 19 18:03:00 mail Some program![1688]: log.Print: Logging in Go!
```

两台机器的输出显示，Linux 机器具有不同的`syslog`配置，这就是`useLog.go`的消息也被写入`/var/log/cisco.log`的原因。

然而，您的主要关注点不应该是日志消息是否会被写入太多文件，而是您是否能够找到它们！

# 处理日志文件

本小节将处理一个包含客户端 IP 地址的日志文件，以创建它们的摘要。Go 文件的名称将是`countIP.go`，并将分为四个部分呈现。请注意，`countIP.go`需要两个参数：日志文件的名称和包含所需信息的字段。由于`countIP.go`不检查给定字段是否包含 IP 地址，因此如果删除其中的一些代码，它也可以用于其他类型的数据。

首先，您将看到程序的预期序言：

```go
package main 

import ( 
   "bufio" 
   "flag" 
   "fmt" 
   "io" 
   "net" 
   "os" 
   "path/filepath" 
   "strings" 
) 
```

第二部分带有以下 Go 代码，这是`main()`函数实现的开始：

```go
func main() { 
   minusCOL := flag.Int("COL", 1, "Column") 
   flag.Parse() 
   flags := flag.Args() 

   if len(flags) == 0 { 
         fmt.Printf("usage: %s <file1> [<file2> [... <fileN]]\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   column := *minusCOL 
   if column < 0 {
         fmt.Println("Invalid Column number!") 
         os.Exit(1) 
   } 
```

`countIP.go`实用程序使用`flag`包，可以处理多个文件。

程序的第三部分如下：

```go
   myIPs := make(map[string]int) 
   for _, filename := range flags { 
         fmt.Println("\t\t", filename) 
         f, err := os.Open(filename) 
         if err != nil { 
               fmt.Printf("error opening file %s\n", err) 
               continue 
         } 
         defer f.Close() 

         r := bufio.NewReader(f) 
         for { 
               line, err := r.ReadString('\n') 

               if err == io.EOF { 
                     break 
               } else if err != nil { 
                     fmt.Printf("error reading file %s", err) 
                     continue 
               } 
```

每个输入文件都是逐行读取的，而`myIPs`映射变量用于保存每个 IP 地址的计数。

`countIP.go`的最后一部分如下：

```go
               data := strings.Fields(line) 
               ip := data[column-1] 
               trial := net.ParseIP(ip) 
               if trial.To4() == nil { 
                     continue 
               } 

               _, ok := myIPs[ip] 
               if ok { 
                     myIPs[ip] = myIPs[ip] + 1 
               } else { 
                     myIPs[ip] = 1 
               } 
         } 
   } 

   for key, _ := range myIPs { 
         fmt.Printf("%s %d\n", key, myIPs[key]) 
   } 
} 
```

这里是魔术发生的地方：首先，您从工作行中提取所需的字段。然后，您使用`net.ParseIP()`函数确保您正在处理有效的 IP 地址：如果您希望程序处理其他类型的数据，应删除使用`net.ParseIP()`函数的 Go 代码。之后，根据当前 IP 地址是否可以在映射中找到，更新`myIPs`映射的内容：您在第二章*，Go 编程*中看到了该代码。最后，您在屏幕上打印`myIPs`映射的内容，完成！

执行`countIP.go`会生成以下输出：

```go
$ go run countIP.go /tmp/log.1 /tmp/log.2
             /tmp/log.1
             /tmp/log.2
164.132.161.85 4
66.102.8.135 17
5.248.196.10 15
180.76.15.10 12
66.249.69.40 142
51.255.65.35 7
95.158.53.56 1
64.183.178.218 31
$ go run countIP.go /tmp/log.1 /tmp/log.2 | wc
    1297    2592   21266
```

然而，如果输出按每个 IP 地址关联的计数排序，将会更好，你可以很容易地通过`sort(1)`Unix 实用程序来实现：

```go
$ go run countIP.go /tmp/log.1 /tmp/log.2 | sort -rn -k2
45.55.38.245 979
159.203.126.63 976
130.193.51.27 698
5.9.63.149 370
77.121.238.13 340
46.4.116.197 308
51.254.103.60 302
51.255.194.31 277
195.74.244.47 201
61.14.225.57 179
69.30.198.242 152
66.249.69.40 142
2.86.9.124 140
2.86.27.46 127
66.249.69.18 125
```

如果你想要前 10 个 IP 地址，你可以使用`head(1)`实用程序过滤前面的输出，如下所示：

```go
$ go run countIP.go /tmp/log.1 /tmp/log.2 | sort -rn -k2 | head
45.55.38.245 979
159.203.126.63 976
130.193.51.27 698
5.9.63.149 370
77.121.238.13 340
46.4.116.197 308
51.254.103.60 302
51.255.194.31 277
195.74.244.47 201
61.14.225.57 179
```

# 文件权限重访

有时我们需要查找文件的 Unix 权限的详细信息。`filePerm.go` Go 实用程序将教你如何读取文件或目录的 Unix 文件权限，并将其打印为二进制数、十进制数和字符串。该程序将分为三部分。第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
) 
```

第二部分如下：

```go
func tripletToBinary(triplet string) string { 
   if triplet == "rwx" { 
         return "111" 
   } 
   if triplet == "-wx" { 
         return "011" 
   } 
   if triplet == "--x" { 
         return "001" 
   } 
   if triplet == "---" { 
         return "000" 
   } 
   if triplet == "r-x" { 
         return "101" 
   } 
   if triplet == "r--" { 
         return "100" 
   } 
   if triplet == "--x" { 
         return "001" 
   } 
   if triplet == "rw-" { 
         return "110" 
   } 
   if triplet == "-w-" { 
         return "010" 
   } 
   return "unknown" 
} 

func convertToBinary(permissions string) string { 
   binaryPermissions := permissions[1:] 
   p1 := binaryPermissions[0:3] 
   p2 := binaryPermissions[3:6] 
   p3 := binaryPermissions[6:9] 
   return tripletToBinary(p1) + tripletToBinary(p2) + tripletToBinary(p3) 
} 
```

在这里，你实现了两个函数，它们将帮助你将一个包含文件权限的九个字符的字符串转换为一个二进制数。例如，`rwxr-x---`字符串将被转换为`111101000`。初始字符串是从`os.Stat()`函数调用中提取的。

最后一部分包含以下 Go 代码：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         fmt.Printf("usage: %s filename\n", filepath.Base(arguments[0])) 
         os.Exit(1) 
   } 

   filename := arguments[1] 
   info, _ := os.Stat(filename) 
   mode := info.Mode() 

   fmt.Println(filename, "mode is", mode) 
   fmt.Println("As string is", mode.String()[1:10]) 
   fmt.Println("As binary is", convertToBinary(mode.String())) 
} 
```

执行`filePerm.go`将生成以下输出：

```go
$ go run filePerm.go .
. mode is drwxr-xr-x
As string is rwxr-xr-x
As binary is 111101101
$ go run filePerm.go /tmp/swtag.log
/tmp/swtag.log mode is -rw-rw-rw-
As string is rw-rw-rw-
As binary is 110110110
```

# 更改文件权限

本节将解释如何将文件或目录的 Unix 权限更改为所需的值；但是，它不会处理粘性位、设置用户 ID 位或设置组 ID 位：不是因为它们难以实现，而是因为在处理系统文件时通常不需要这些功能。

该实用程序的名称将是`setFilePerm.go`，它将分为四个部分呈现。新的文件权限将以`rwxrw-rw-`等九个字符的字符串形式给出。

`setFilePerm.go`的第一部分包含了预期的前言 Go 代码：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
   "strconv" 
) 
```

第二部分是`tripletToBinary()`函数的实现，你在上一节中看到了：

```go
func tripletToBinary(triplet string) string { 
   if triplet == "rwx" { 
         return "111" 
   } 
   if triplet == "-wx" { 
         return "011" 
   } 
   if triplet == "--x" { 
         return "001" 
   } 
   if triplet == "---" { 
         return "000" 
   } 
   if triplet == "r-x" { 
         return "101" 
   } 
   if triplet == "r--" { 
         return "100" 
   } 
   if triplet == "--x" { 
         return "001" 
   } 
   if triplet == "rw-" { 
         return "110" 
   } 
   if triplet == "-w-" { 
         return "010" 
   } 
   return "unknown" 
} 
```

第三部分包含以下 Go 代码：

```go
func convertToBinary(permissions string) string { 
   p1 := permissions[0:3] 
   p2 := permissions[3:6] 
   p3 := permissions[6:9] 

   p1 = tripletToBinary(p1) 
   p2 = tripletToBinary(p2) 
   p3 = tripletToBinary(p3) 

   p1Int, _ := strconv.ParseInt(p1, 2, 64) 
   p2Int, _ := strconv.ParseInt(p2, 2, 64) 
   p3Int, _ := strconv.ParseInt(p3, 2, 64) 

   returnValue := p1Int*100 + p2Int*10 + p3Int 
   tempReturnValue := int(returnValue) 
   returnString := "0" + strconv.Itoa(tempReturnValue) 
   return returnString 
} 
```

在这里，函数的名称是误导性的，因为它并不返回一个二进制数：这是我的错。

最后一部分包含以下 Go 代码：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) != 3 { 
         fmt.Printf("usage: %s filename permissions\n",  
filepath.Base(arguments[0])) 
         os.Exit(1) 
   } 

   filename, _ := filepath.EvalSymlinks(arguments[1]) 
   permissions := arguments[2] 
   if len(permissions) != 9 { 
         fmt.Println("Permissions should be 9 characters  
(rwxrwxrwx):", permissions) 
         os.Exit(-1) 
   } 

   bin := convertToBinary(permissions) 
   newPerms, _ := strconv.ParseUint(bin, 0, 32) 
   newMode := os.FileMode(newPerms) 
   os.Chmod(filename, newMode) 
} 
```

在这里，你获取`convertToBinary()`的返回值，并将其转换为`os.FileMode()`变量，以便与`os.Chmod()`函数一起使用。

运行`setFilePerm.go`将生成以下结果：

```go
$ go run setFilePerm.go /tmp/swtag.log rwxrwxrwx
$ ls -l /tmp/swtag.log
-rwxrwxrwx  1 mtsouk  wheel  7066 May 22 19:17 /tmp/swtag.log
$ go run setFilePerm.go /tmp/swtag.log rwxrwx---
$ ls -l /tmp/swtag.log
-rwxrwx---  1 mtsouk  wheel  7066 May 22 19:17 /tmp/swtag.log
```

# 查找文件的其他信息

Unix 文件的最重要信息是它的所有者和它的组，本节将教你如何使用 Go 代码找到它们。`findOG.go`实用程序接受文件列表作为其命令行参数，并返回每个文件的所有者和组。它的 Go 代码将分为三部分。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
   "syscall" 
) 
```

第二部分如下：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         fmt.Printf("usage: %s <files>\n", filepath.Base(arguments[0])) 
         os.Exit(1) 
   } 

   for _, filename := range arguments[1:] { 
         fileInfo, err := os.Stat(filename) 
         if err != nil { 
               fmt.Println(err) 
               continue 
         } 
```

在这一部分，你调用`os.Stat()`函数来确保你要处理的文件存在。

`findOG.go`的最后一部分带有以下 Go 代码：

```go
         fmt.Printf("%+v\n", fileInfo.Sys()) 
         fmt.Println(fileInfo.Sys().(*syscall.Stat_t).Uid) 
         fmt.Println(fileInfo.Sys().(*syscall.Stat_t).Gid) 
   } 
} 
```

是的，这是你在本书中迄今为止看到的最神秘的代码，它使用`os.Stat()`的返回值来提取所需的信息。此外，它也不是可移植的，这意味着它可能在你的 Unix 变体上无法工作，也不能保证它将在 Go 的未来版本中继续工作！

有时看起来很容易的任务可能会花费比预期更多的时间。其中一个任务就是`findOG.go`程序。这主要是因为 Go 没有一种简单且可移植的方法来找出文件的所有者和组。希望这在未来会有所改变。

在 macOS Sierra 或 Mac OS X 上执行`findOG.go`将生成以下输出：

```go
$ go run findOG.go /tmp/swtag.log
&{Dev:16777218 Mode:33206 Nlink:1 Ino:50547755 Uid:501 Gid:0 Rdev:0 Pad_cgo_0:[0 0 0 0] Atimespec:{Sec:1495297106 Nsec:0} Mtimespec:{Sec:1495297106 Nsec:0} Ctimespec:{Sec:1495297106 Nsec:0} Birthtimespec:{Sec:1495044975 Nsec:0} Size:2586 Blocks:8 Blksize:4096 Flags:0 Gen:0 Lspare:0 Qspare:[0 0]}
501
0
$ ls -l /tmp/swtag.log
-rw-rw-rw-  1 mtsouk  wheel  2586 May 20 19:18 /tmp/swtag.log
$ grep wheel /etc/group
wheel:*:0:root 
```

在这里，你可以看到`fileInfo.Sys()`调用以某种令人困惑的格式返回了大量文件信息：这些信息类似于对`stat(2)`的 C 调用的信息。输出的第一行是`os.Stat.Sys()`调用的内容，而第二行是文件所有者的用户 ID（`501`），第三行是文件所有者的组 ID（`0`）。

在 Debian Linux 机器上执行`findOG.go`将生成以下输出：

```go
$ go run findOG.go /home/mtsouk/connections.data
&{Dev:2048 Ino:1196167 Nlink:1 Mode:33188 Uid:1000 Gid:1000 X__pad0:0 Rdev:0 Size:9626800 Blksize:4096 Blocks:18840 Atim:{Sec:1412623801 Nsec:0} Mtim:{Sec:1495307521 Nsec:929812185} Ctim:{Sec:1495307521 Nsec:929812185} X__unused:[0 0 0]}
1000
1000
$ ls -l /home/mtsouk/connections.data
-rw-r--r-- 1 mtsouk mtsouk 9626800 May 20 22:12 /home/mtsouk/connections.data
code$ grep ^mtsouk /etc/group
mtsouk:x:1000:
```

好消息是，`findOG.go`在 macOS Sierra 和 Debian Linux 上都可以工作，尽管 macOS Sierra 使用的是 Go 版本 1.8.1，而 Debian Linux 使用的是 Go 版本 1.3.3！

大部分呈现的 Go 代码将在本章后面用于实现`userFiles.go`实用程序。

# 更多模式匹配示例

本节将介绍与本书迄今为止所见模式更困难的正则表达式。只需记住，正则表达式和模式匹配是您应该通过实验和有时失败来学习的实用主题，而不是通过阅读来学习。

如果您在 Go 中非常小心地处理正则表达式，您几乎可以读取或更改 Unix 系统中几乎所有以纯文本格式存在的系统文件。只是在修改系统文件时要特别小心！

# 一个简单的模式匹配示例

本节的示例将改进`countIP.go`实用程序的功能，通过开发一个自动检测具有 IP 地址的字段的程序；因此，它不需要用户定义包含 IP 地址的每个日志条目的字段。为了简化事情，创建的程序将只处理每行的第一个 IP 地址：`findIP.go`接受一个命令行参数，即要处理的日志文件的名称。程序将分为四个部分。

`findIP.go`的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "net" 
   "os" 
   "path/filepath" 
   "regexp" 
) 
```

第二部分是在一个函数的帮助下发生大部分魔术的地方：

```go
func findIP(input string) string { 
   partIP := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])" 
   grammar := partIP + "\\." + partIP + "\\." + partIP + "\\." + partIP 
   matchMe := regexp.MustCompile(grammar) 
   return matchMe.FindString(input) 
} 
```

考虑到我们只想匹配由点分隔的 0-255 范围内的四个十进制数，正则表达式非常复杂，这主要表明当您想要有条不紊地进行时，正则表达式可能非常复杂。

但让我更详细地解释一下。IP 地址由四部分组成，用点分隔。每个部分的值可以在 0 到 255 之间，这意味着数字 257 不是可接受的值：这是正则表达式如此复杂的主要原因。第一种情况是介于 250 和 255 之间的数字。第二种情况是介于 200 和 249 之间的数字，第三种情况是介于 100 和 199 之间的数字。最后一种情况是捕获 0 到 99 之间的值。

`findIP.go`的第三部分如下：

```go
func main() { 
   if len(os.Args) != 2 { 
         fmt.Printf("usage: %s logFile\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 
   filename := os.Args[1] 

   f, err := os.Open(filename) 
   if err != nil { 
         fmt.Printf("error opening file %s\n", err) 
         os.Exit(-1) 
   } 
   defer f.Close() 

   myIPs := make(map[string]int) 
   r := bufio.NewReader(f) 
   for { 
         line, err := r.ReadString('\n') 
         if err == io.EOF { 
               break 
         } else if err != nil { 
               fmt.Printf("error reading file %s", err) 
               break 
         } 
```

在这里，您使用`bufio.NewReader()`逐行读取输入日志文件。

最后一部分包含以下 Go 代码，用于处理正则表达式的匹配项：

```go
         ip := findIP(line) 
         trial := net.ParseIP(ip) 
         if trial.To4() == nil { 
               continue 
         } else { 
               _, ok := myIPs[ip] 
               if ok { 
                     myIPs[ip] = myIPs[ip] + 1 
               } else { 
                     myIPs[ip] = 1 
               } 
         } 
   } 
   for key, _ := range myIPs { 
         fmt.Printf("%s %d\n", key, myIPs[key]) 
   } 
} 
```

正如您所看到的，`findIP.go`对由执行模式匹配操作的函数找到的 IP 执行了额外的检查，使用`net.ParseIP()`；这主要是因为 IP 地址非常棘手，因此最好是再次检查它们！此外，这会捕获`findIP()`返回空值的情况，因为在处理的行中未找到有效的 IP。程序在退出之前做的最后一件事是打印`myIPs`映射的内容。

考虑一下，您可以用少量的 Go 代码开发多少令人难以置信和有用的实用程序：这真是令人惊讶！

在 Linux 机器上执行`findIP.go`以处理`/var/log/auth.log`日志文件将创建以下输出：

```go
$ wc /var/log/auth.log
  1499647  20313719 155224677 /var/log/auth.log
$ go run findIP.go /var/log/auth.log
39.114.101.107 1003
111.224.233.41 10
189.41.147.179 306
55.31.112.181 1
5.141.131.102 10
171.60.251.143 30
218.237.65.48 1
24.16.210.120 8
199.115.116.50 3
139.160.113.181 1
```

您可以按 IP 被发现的次数对先前的输出进行排序，并显示前 10 个最受欢迎的 IP 地址，如下所示：

```go
$ go run findIP.go /var/log/auth.log | sort -nr -k2 | head
218.65.30.156 102533
61.177.172.27 37746
218.65.30.43 34640
109.74.11.18 32870
61.177.172.55 31968
218.65.30.124 31649
59.63.188.3 30970
61.177.172.28 30023
116.31.116.30 29314
61.177.172.14 28615
```

因此，在这种情况下，`findIP.go`实用程序用于检查您的 Linux 机器的安全性！

# 模式匹配的高级示例

在本节中，您将学习如何交换文本文件每行的两个字段的值，前提是它们的格式正确。这主要发生在日志文件或其他文本文件中，您希望扫描某种类型的数据的行，如果找到数据，可能需要对其进行某些操作：在这种情况下，您将更改两个值的位置。

程序的名称将是`swapRE.go`，它将分为四个部分。再次，该程序将逐行读取文本文件，并尝试匹配所需的字符串后进行交换。该实用程序将在屏幕上打印新文件的内容；将结果保存到新文件是用户的责任。`swapRE.go`期望处理的日志条目格式类似于以下内容：

```go
127.0.0.1 - - [24/May/2017:06:41:11 +0300] "GET /contact HTTP/1.1" 200 6048 "http://www.mtsoukalos.eu/" "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" 132953
```

程序将交换的上一行条目是[`24/May/2017:06:41:11 +0300`]和`132953`，它们分别是日期和时间以及浏览器获取所需信息所花费的时间；程序期望在每行末尾找到这些内容。但是，正则表达式还检查日期和时间是否以正确的格式以及每个日志条目的最后一个字段是否确实是数字。

正如您将看到的，有时在 Go 中使用正则表达式可能会令人困惑，主要是因为正则表达式通常相对难以构建。

`swapRE.go`的第一部分将是预期的序言：

```go
package main 

import ( 
   "bufio" 
   "flag" 
   "fmt" 
   "io" 
   "os" 
   "regexp" 
) 
```

第二部分包括以下 Go 代码：

```go
func main() { 
   flag.Parse() 
   if flag.NArg() != 1 { 
         fmt.Println("Please provide one log file to process!") 
         os.Exit(-1) 
   } 
   numberOfLines := 0 
   numberOfLinesMatched := 0 

   filename := flag.Arg(0) 
   f, err := os.Open(filename) 
   if err != nil { 
         fmt.Printf("error opening file %s", err) 
         os.Exit(1) 
   } 
   defer f.Close() 
```

这里没有什么特别有趣或新的。

第三部分如下：

```go
   r := bufio.NewReader(f) 
   for { 
         line, err := r.ReadString('\n') 
         if err == io.EOF { 
               break 
         } else if err != nil { 
               fmt.Printf("error reading file %s", err) 
         } 
```

这是允许您逐行处理输入文件的 Go 代码。

`swapRE.go`的最后一部分如下：

```go
         numberOfLines++ 
         r := regexp.MustCompile(`(.*) (\[\d\d\/(\w+)/\d\d\d\d:\d\d:\d\d:\d\d(.*)\]) (.*) (\d+)`) 
         if r.MatchString(line) { 
               numberOfLinesMatched++ 
               match := r.FindStringSubmatch(line) 
               fmt.Println(match[1], match[6], match[5], match[2]) 
         } 
   } 
   fmt.Println("Line processed:", numberOfLines) 
   fmt.Println("Line matched:", numberOfLinesMatched) 
} 
```

正如您可以想象的那样，像这里呈现的复杂正则表达式一样，是逐步构建的，而不是一次性完成的。即使在这种情况下，您可能仍然会在过程中多次失败，因为即使在复杂正则表达式中出现最微小的错误也会导致它不符合您的期望：在这里，广泛的测试是关键！

正则表达式中使用的括号允许您在之后引用每个匹配项，并且在您想要处理已匹配内容时非常方便。在这里，您想要找到一个`[`字符，然后是两位数字，它们将是月份的日期，然后是一个单词，它将是月份的名称，然后是四位数字，它们将是年份。接下来，匹配任何其他内容，直到找到一个`]`字符。然后匹配每行末尾的所有数字。

请注意，可能存在编写相同正则表达式的替代方法。这里的一般建议是以清晰且易于理解的方式编写它。

执行`swapRE.go`，一个小的测试日志文件将生成以下输出：

```go
$ go run swapRE.go /tmp/log.log
127.0.0.1 - - 28787 "GET /taxonomy/term/35/feed HTTP/1.1" 200 2360 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" [24/May/2017:07:04:48 +0300]
- - 32145 HTTP/1.1" 200 2616 "http://www.mtsoukalos.eu/" "Mozilla/5.0 (compatible; inoreader.com-like FeedFetcher-Google)" [24/May/2017:07:09:24 +0300]
Line processed: 3
Line matched: 2
```

# 使用正则表达式重命名多个文件

最后一节关于模式匹配和正则表达式将处理文件名，并允许您重命名多个文件。正如您可以猜到的那样，在程序中将使用 walk 函数，而正则表达式将匹配您想要重命名的文件名。

处理文件时，您应该特别小心，因为您可能会意外地破坏东西！简而言之，不要在生产服务器上测试这样的实用程序。

该实用程序的名称将是`multipleMV.go`，它将分为三个部分。`multipleMV.go`将做的是在与给定正则表达式匹配的每个文件名前插入一个字符串。

第一部分是预期的序言：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "path/filepath" 
   "regexp" 
) 

var RE string
var renameString string 
```

这两个全局变量可以避免在函数中使用许多参数。另外，由于`walk()`函数的签名在一段时间内不会改变，所以无法将它们作为参数传递给`walk()`。因此，在这种情况下，有两个全局参数会使事情变得更容易和简单。

第二部分包含以下 Go 代码：

```go
func walk(path string, f os.FileInfo, err error) error { 
   regex, err := regexp.Compile(RE) 
   if err != nil { 
         fmt.Printf("Error in RE: %s\n", RE) 
         return err 
   } 

   if path == "." { 
         return nil 
   } 
   nameOfFile := filepath.Base(path) 
   if regex.MatchString(nameOfFile) { 
         newName := filepath.Dir(path) + "/" + renameString + "_" + nameOfFile 
         os.Rename(path, newName) 
   } 
   return nil 
} 
```

程序的所有功能都嵌入在`walk()`函数中。成功匹配后，新文件名将存储在`newName`变量中，然后执行`os.Rename()`函数。

`multipleMV.go`的最后一部分是`main()`函数的实现：

```go
func main() { 
   flag.Parse() 
   if flag.NArg() != 3 { 
         fmt.Printf("Usage: %s REGEXP RENAME Path", filepath.Base(os.Args[0])) 
         os.Exit(-1) 
   } 

   RE = flag.Arg(0) 
   renameString = flag.Arg(1) 
   Path := flag.Arg(2) 
   Path, _ = filepath.EvalSymlinks(Path) 
   filepath.Walk(Path, walk) 
} 
```

在这里，没有什么是你以前没有见过的：唯一有趣的是调用`filepath.EvalSymlinks()`，以便不必处理符号链接。

使用 `multipleMV.go` 就像运行以下命令一样简单：

```go
$ ls -l /tmp/swtag.log
-rw-rw-rw-  1 mtsouk  wheel  446 May 22 09:18 /tmp/swtag.log
$ go run multipleMV.go 'log$' new /tmp
$ ls -l /tmp/new_swtag.log
-rw-rw-rw-  1 mtsouk  wheel  446 May 22 09:18 /tmp/new_swtag.log
$ go run multipleMV.go 'log$' new /tmp
$ ls -l /tmp/new_new_swtag.log
-rw-rw-rw-  1 mtsouk  wheel  446 May 22 09:18 /tmp/new_new_swtag.log
$ go run multipleMV.go 'log$' new /tmp
$ ls -l /tmp/new_new_new_swtag.log
-rw-rw-rw-  1 mtsouk  wheel  446 May 22 09:18 /tmp/new_new_new_swtag.log 
```

# 重新访问搜索文件

本节将教你如何使用用户 ID、组 ID 和文件权限等条件来查找文件。尽管这一节本来可以包含在第五章 *文件和目录* 中，但我决定把它放在这里，因为有时你会想要使用这种信息来通知系统管理员系统出了问题。

# 查找用户的用户 ID

这一小节将介绍一个程序，它显示给定用户名的用户 ID，这或多或少是 `id -u` 实用程序的输出：

```go
$ id -u
33
$ id -u root
0
```

存在一个名为 `user` 的 Go 包，可以在 `os` 包下找到，可以帮助你实现所需的任务，这一点不应该让你感到惊讶。程序的名称将是 `userID.go`，它将分为两部分。如果你没有给 `userID.go` 传递命令行参数，它将打印当前用户的用户 ID；否则，它将打印给定用户名的用户 ID。

`userID.go` 的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "os/user" 
) 

func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         uid := os.Getuid() 
         fmt.Println(uid) 
         return 
   } 
```

`os.Getuid()` 函数返回当前用户的用户 ID。

`userID.go` 的第二部分包含以下 Go 代码：

```go
   username := arguments[1] 
   u, err := user.Lookup(username) 
   if err != nil { 
         fmt.Println(err) 
         return 
   } 
   fmt.Println(u.Uid) 
}

```

给定用户名，`user.Lookup()` 函数返回一个 `user.User` 复合值。我们只会使用该复合值的 `Uid` 字段来查找给定用户名的用户 ID。

执行 `userID.go` 将生成以下输出：

```go
$ go run userID.go
501
$ go run userID.go root
0
$ go run userID.go doesNotExist
user: unknown user doesNotExist
```

# 查找用户所属的所有组

每个用户可以属于多个组：本节将展示如何找出给定用户名的用户属于哪些组的列表。

实用程序的名称将是 `listGroups.go`，它将分为四部分。`listGroups.go` 的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "os/user" 
) 
```

第二部分包含以下 Go 代码：

```go
func main() { 
   arguments := os.Args 
   var u *user.User 
   var err error 
   if len(arguments) == 1 { 
         u, err = user.Current() 
         if err != nil { 
               fmt.Println(err) 
               return 
         } 
```

当没有命令行参数时，`listGroups.go` 采用的方法与 `userID.go` 中找到的方法类似。然而，有一个很大的区别，这一次你不需要当前用户的用户 ID，而是需要当前用户的用户名；所以你调用 `user.Current()`，它返回一个 `user.User` 值。

第三部分包含以下 Go 代码：

```go
   } else { 
         username := arguments[1] 
         u, err = user.Lookup(username) 
         if err != nil { 
               fmt.Println(err) 
               return 
         } 
   } 
```

因此，如果给程序传递了命令行参数，它将通过 `user.Lookup()` 函数处理前面的代码，该函数还返回一个 `user.User` 值。

最后一部分包含以下 Go 代码：

```go
   gids, _ := u.GroupIds() 
   for _, gid := range gids { 
         group, err := user.LookupGroupId(gid) 
         if err != nil { 
               fmt.Println(err) 
               continue 
         } 
         fmt.Printf("%s(%s) ", group.Gid, group.Name) 
   } 
   fmt.Println() 
} 
```

在这里，通过调用 `u.GroupIds()` 函数，你可以获得用户（由 `u` 变量表示）所属的组 ID 列表。然后，你需要一个 `for` 循环来遍历所有列表元素并打印它们。应该明确指出，这个列表存储在 `u` 中；也就是说，一个 `user.User` 值。

执行 `listGroups.go` 将生成以下输出：

```go
$ go run listGroups.go
    20(staff) 701(com.apple.sharepoint.group.1) 12(everyone) 61(localaccounts) 79(_appserverusr) 80(admin) 81(_appserveradm) 98(_lpadmin) 33(_appstore) 100(_lpoperator) 204(_developer) 395(com.apple.access_ftp) 398(com.apple.access_screensharing) 399(com.apple.access_ssh)
$ go run listGroups.go www
70(_www) 12(everyone) 61(localaccounts) 701(com.apple.sharepoint.group.1) 100(_lpoperator)
```

`listGroups.go` 的输出比 `id -G -n` 和 `groups` 命令的输出要丰富得多：

```go
$ id -G -n
staff com.apple.sharepoint.group.1 everyone localaccounts _appserverusr admin _appserveradm _lpadmin _appstore _lpoperator _developer com.apple.access_ftp com.apple.access_screensharing com.apple.access_ssh
$ groups
staff com.apple.sharepoint.group.1 everyone localaccounts _appserverusr admin _appserveradm _lpadmin _appstore _lpoperator _developer com.apple.access_ftp com.apple.access_screensharing com.apple.access_ssh
```

# 查找属于给定用户或不属于给定用户的文件

这一小节将创建一个 Go 程序，扫描目录树并显示属于给定用户或不属于给定用户的文件。程序的名称将是 `userFiles.go`。在其默认操作模式下，`userFiles.go` 将显示所有属于给定用户名的文件；当使用 `-no` 标志时，它将只显示不属于给定用户名的文件。

`userFiles.go` 的代码将分为四部分。

第一部分如下：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "os/user" 
   "path/filepath" 
   "strconv" 
   "syscall" 
) 

var uid int32 = 0
var INCLUDE bool = true 
```

将 `INCLUDE` 和 `uid` 声明为全局变量的原因是你希望它们都可以从程序的任何地方访问。此外，由于 `walkFunction()` 的签名不能改变：只有它的名称可以改变：使用全局变量对开发人员更方便。

第二部分包含以下 Go 代码：

```go
func userOfFIle(filename string) int32 { 
   fileInfo, err := os.Stat(filename) 
   if err != nil { 
         fmt.Println(err) 
         return 1000000 
   } 
   UID := fileInfo.Sys().(*syscall.Stat_t).Uid 
   return int32(UID) 
} 
```

使用名为 `UID` 的局部变量可能是一个不好的选择，因为有一个名为 `uid` 的全局变量！全局变量的更好名称应该是 `gUID`。请注意，关于返回 `UID` 变量的调用方式的解释，您应该搜索 Go 中的接口和类型转换，因为讨论这个超出了本书的范围。

第三部分包含以下 Go 代码：

```go
func walkFunction(path string, info os.FileInfo, err error) error { 
   _, err = os.Lstat(path) 
   if err != nil { 
         return err 
   } 

   if userOfFIle(path) == uid && INCLUDE { 
         fmt.Println(path) 
   } else if userOfFIle(path) != uid && !(INCLUDE) { 
         fmt.Println(path) 
   } 

   return err 
} 
```

在这里，您可以看到一个遍历函数的实现，该函数将访问给定目录树中的每个文件和目录，以便仅打印所需的文件名。

实用程序的最后部分包含以下 Go 代码：

```go
func main() { 
   minusNO := flag.Bool("no", true, "Include") 
   minusPATH := flag.String("path", ".", "Path to Search") 
   flag.Parse() 
   flags := flag.Args() 

   INCLUDE = *minusNO 
   Path := *minusPATH 

   if len(flags) == 0 { 
         uid = int32(os.Getuid()) 
   } else { 
         u, err := user.Lookup(flags[0]) 
         if err != nil { 
               fmt.Println(err) 
               os.Exit(1) 
         } 
         temp, err := strconv.ParseInt(u.Uid, 10, 32) 
         uid = int32(temp) 
   } 

   err := filepath.Walk(Path, walkFunction) 
   if err != nil { 
         fmt.Println(err) 
   } 
} 
```

在调用 `filepath.Walk()` 函数之前，您需要处理 `flag` 包的配置。

执行 `userFiles.go` 会生成以下输出：

```go
$ go run userFiles.go -path=/tmp www-data
/tmp/.htaccess
/tmp/update-cache-2a113cac
/tmp/update-extraction-2a113cac
```

如果您没有给出任何命令行参数或标志，`userFiles.go` 实用程序将假定您想要搜索当前目录中属于当前用户的文件：

```go
$ go run userFiles.go
.
appendData.go
countIP.go
```

因此，为了找到 `/srv/www/www.highiso.net` 目录中不属于 `www-data` 用户的所有文件，您应该执行以下命令：

```go
$ go run userFiles.go -no=false -path=/srv/www/www.highiso.net www-data
/srv/www/www.highiso.net/list.files
/srv/www/www.highiso.net/public_html/wp-content/.htaccess
/srv/www/www.highiso.net/public_html.UnderCon/.htaccess
```

# 根据权限查找文件

现在您知道如何找到文件的 Unix 权限后，可以改进上一章中的 `regExpFind.go` 实用程序，以支持基于文件权限的搜索；但是，为了避免在这里没有任何实际原因的情况下呈现一个非常大的 Go 程序，所以呈现的程序将是自主的，并且只支持根据权限查找文件。新实用程序的名称将是 `findPerm.go`，将分为四部分呈现。权限将以 `ls(1)` 命令返回的格式作为字符串在命令行中给出（`rwxr-xr--`）。

实用程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
) 

var PERMISSIONS string
```

`PERMISSIONS` 变量是全局的，以便从程序的任何地方访问，并且因为 `walkFunction()` 的签名不能更改。

`findPerm.go` 的第二部分包含以下代码：

```go
func permissionsOfFIle(filename string) string { 
   info, err := os.Stat(filename) 
   if err != nil { 
         return "-1" 
   } 
   mode := info.Mode() 
   return mode.String()[1:10] 
} 
```

第三部分是 `walkFunction()` 的实现：

```go
func walkFunction(path string, info os.FileInfo, err error) error { 
   _, err = os.Lstat(path) 
   if err != nil { 
         return err 
   } 

   if permissionsOfFIle(path) == PERMISSIONS { 
         fmt.Println(path) 
   } 
   return err 
} 
```

`findPerm.go` 的最后部分如下：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) != 3 { 
         fmt.Printf("usage: %s RootDirectory permissions\n",  
filepath.Base(arguments[0])) 
         os.Exit(1) 
   } 

   Path := arguments[1] 
   Path, _ = filepath.EvalSymlinks(Path) 
   PERMISSIONS = arguments[2] 

   err := filepath.Walk(Path, walkFunction) 
   if err != nil { 
         fmt.Println(err) 
   } 
} 
```

执行 `findPerm.go` 会生成以下输出：

```go
$ go run findPerm.go /tmp rw-------
/private/tmp/.adobeLockFile
$ ls -l /private/tmp/.adobeLockFile
-rw-------  1 mtsouk  wheel  0 May 19 14:36 /private/tmp/.adobeLockFile
```

# 日期和时间操作

本节将向您展示如何在 Go 中处理日期和时间。这项任务可能看起来微不足道，但当您想要同步诸如日志条目和错误消息之类的事物时，它可能非常重要。我们将首先说明 `time` 包的一些功能。

# 玩转日期和时间

本节将介绍一个名为 `dateTime.go` 的小型 Go 程序，展示了如何在 Go 中处理时间和日期。`dateTime.go` 的代码将分为三部分呈现。第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 

func main() { 

   fmt.Println("Epoch time:", time.Now().Unix()) 
   t := time.Now() 
   fmt.Println(t, t.Format(time.RFC3339)) 
   fmt.Println(t.Weekday(), t.Day(), t.Month(), t.Year()) 
   time.Sleep(time.Second) 
   t1 := time.Now() 
   fmt.Println("Time difference:", t1.Sub(t)) 

   formatT := t.Format("01 January 2006") 
   fmt.Println(formatT) 
   loc, _ := time.LoadLocation("Europe/London") 
   londonTime := t.In(loc) 
   fmt.Println("London:", londonTime) 
```

在这部分中，您可以看到如何将日期从一种格式转换为另一种格式，以及如何在不同时区找到日期和时间。`main()` 函数开头使用的 `time.Now()` 函数返回当前时间。

第二部分如下：

```go
   myDate := "23 May 2017" 
   d, _ := time.Parse("02 January 2006", myDate) 
   fmt.Println(d) 

   myDate1 := "23 May 2016" 
   d1, _ := time.Parse("02 February 2006", myDate1) 
   fmt.Println(d1)

```

可以在 [`golang.org/src/time/format.go`](https://golang.org/src/time/format.go) 找到用于创建自己的解析格式的常量列表。Go 不像其他编程语言那样以 DDYYYYMM 或 %D %Y %M 的形式定义日期或时间的格式，而是使用自己的方法。

在这里，您可以看到如何读取一个字符串并尝试将其转换为有效的日期，成功地（`d`）和不成功地（`d1`）。`d1` 变量的问题在于 `format` 字符串中使用了 `February`：您应该改用 `January`。

`dateTime.go` 的最后部分带有以下 Go 代码：

```go
   myDT := "Tuesday 23 May 2017 at 23:36" 
   dt, _ := time.Parse("Monday 02 January 2006 at 15:04", myDT) 
   fmt.Println(dt) 
} 
```

本部分还展示了如何将字符串转换为日期和时间，前提是它是预期的格式。

执行 `dateTime.go` 会生成以下输出：

```go
$ go run dateTime.go
Epoch time: 1495572122
2017-05-23 23:42:02.459713551 +0300 EEST 2017-05-23T23:42:02+03:00
Tuesday 23 May 2017
Time difference: 1.001749054s
05 May 2017
London: 2017-05-23 21:42:02.459713551 +0100 BST
2017-05-23 00:00:00 +0000 UTC
0001-01-01 00:00:00 +0000 UTC
2017-05-23 23:36:00 +0000 UTC
```

# 重新格式化日志文件中的时间

本节将展示如何实现一个程序，该程序读取包含日期和时间信息的日志文件，以便转换每个日志条目中找到的时间格式。当您有来自不同时区的不同服务器的日志文件，并且希望同步它们的时间以便从它们的数据创建报告或将它们存储到数据库中以便以后处理它们时，可能需要执行此操作。

所呈现的程序的名称将是`dateTimeLog.go`，并且将分为四个部分。

第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "flag" 
   "fmt" 
   "io" 
   "os" 
   "regexp" 
   "strings" 
   "time" 
) 
```

第二部分包含以下 Go 代码：

```go
func main() { 
   flag.Parse() 
   if flag.NArg() != 1 { 
         fmt.Println("Please provide one log file to process!") 
         os.Exit(-1) 
   } 

   filename := flag.Arg(0) 
   f, err := os.Open(filename) 
   if err != nil { 
         fmt.Printf("error opening file %s", err) 
         os.Exit(1) 
   } 
   defer f.Close() 
```

在这里，您只需配置`flag`包并打开输入文件以进行读取。

程序的第三部分如下：

```go
   r := bufio.NewReader(f) 
   for { 
         line, err := r.ReadString('\n') 
         if err == io.EOF { 
               break 
         } else if err != nil { 
               fmt.Printf("error reading file %s", err) 
         } 
```

在这里，您逐行读取输入文件。

最后一部分如下：

```go
         r := regexp.MustCompile(`.*\[(\d\d\/\w+/\d\d\d\d:\d\d:\d\d:\d\d.*)\] .*`) 
         if r.MatchString(line) { 
               match := r.FindStringSubmatch(line) 
               d1, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[1]) 
               if err != nil { 
                     fmt.Println(err) 
               } 
               newFormat := d1.Format(time.RFC3339) 
               fmt.Print(strings.Replace(line, match[1], newFormat, 1)) 
         } 
   } 
} 
```

这里的基本思想是，一旦找到匹配项，就使用`time.Parse()`解析找到的日期和时间，然后使用`time.Format()`函数将其转换为所需的格式。此外，在使用`strings.Replace()`打印之前，您将初始匹配项替换为`time.Format()`函数的输出。

执行`dateTimeLog.go`将生成以下输出：

```go
$ go run dateTimeLog.go /tmp/log.log
127.0.0.1 - - [2017-05-24T07:04:48+03:00] "GET /taxonomy/term/35/feed HTTP/1.1" 200 2360 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" 28787
- - [2017-05-24T07:09:24+03:00] HTTP/1.1" 200 2616 "http://www.mtsoukalos.eu/" "Mozilla/5.0 (compatible; inoreader.com-like FeedFetcher-Google)" 32145
[2017-05-24T07:38:08+03:00] "GET /tweets?page=181 HTTP/1.1" 200 8605 "-" "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)" 100531
```

# 旋转日志文件

日志文件由于不断写入数据而不断变得越来越大；最好有一种旋转它们的技术。本节将介绍这样的技术。Go 程序的名称将是`rotateLog.go`，并且将分为三个部分。请注意，要旋转日志文件，进程必须是打开该日志文件进行写入的进程。尝试旋转您不拥有的日志可能会在您的 Unix 机器上创建问题，应该避免！

在这里，您还将看到另一种技术，即使用自己的日志文件存储日志条目，借助`log.SetOutput()`的帮助：成功调用`log.SetOutput()`后，对`log.Print()`的每个函数调用都将使输出转到用作`log.SetOutput()`参数的日志文件。

`rotateLog.go`的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
   "strconv" 
   "time" 
) 

var TOTALWRITES int = 0 
var ENTRIESPERLOGFILE int = 100 
var WHENTOSTOP int = 230 
var openLogFile os.File 
```

使用硬编码变量来定义程序何时停止被认为是一种良好的做法：这是因为您没有其他方法告诉`rotateLog.go`停止。但是，如果您在编译的程序中使用`rotateLog.go`实用程序的功能，则此类变量应作为命令行参数给出，因为您不应该重新编译程序以更改程序的行为方式！

`rotateLog.go`的第二部分如下：

```go
func rotateLogFile(filename string) error { 
   openLogFile.Close() 
   os.Rename(filename, filename+"."+strconv.Itoa(TOTALWRITES)) 
   err := setUpLogFile(filename) 
   return err 
} 

func setUpLogFile(filename string) error { 
   openLogFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) 
   if err != nil { 
         return err 
   } 
   log.SetOutput(openLogFile) 
   return nil 
} 
```

在这里，您定义了名为`rotateLogFile()`的 Go 函数，用于旋转所需的日志文件，这是程序的最重要部分。`setUpLogFile()`函数在旋转日志文件后帮助您重新启动日志文件。这里还展示了使用`log.SetOutput()`告诉程序在哪里写入日志条目。请注意，您应该使用`os.OpenFile()`打开日志文件，因为`os.Open()`对于`log.SetOutput()`不起作用，而`os.Open()`会打开文件进行写入！

最后一部分如下：

```go
func main() { 
   numberOfLogEntries := 0 
   filename := "/tmp/myLog.log" 
   err := setUpLogFile(filename) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(-1) 
   } 

   for { 
         log.Println(numberOfLogEntries, "This is a test log entry") 
         numberOfLogEntries++ 
         TOTALWRITES++ 
         if numberOfLogEntries > ENTRIESPERLOGFILE { 
               rotateLogFile(filename)
               numberOfLogEntries = 0 
         } 
         if TOTALWRITES > WHENTOSTOP { 
               rotateLogFile(filename)
               break 
         } 
         time.Sleep(time.Second) 
   } 
   fmt.Println("Wrote", TOTALWRITES, "log entries!") 
} 
```

在这部分中，`main()`函数在计算到目前为止已写入的条目数的同时继续向日志文件写入数据。当达到定义的条目数（`ENTRIESPERLOGFILE`）时，`main()`函数将调用`rotateLogFile()`函数，该函数将为我们完成繁重的工作。在真实的程序中，您很可能不需要调用`time.Sleep()`来延迟程序的执行。对于这个特定的程序，`time.Sleep()`将为您提供时间来使用`tail -f`检查日志文件，如果您选择这样做的话。

运行`rotateLog.go`将在屏幕上和`/tmp`目录中生成以下输出：

```go
$ go run rotateLog.go
Wrote 231 log entries!
$ wc /tmp/myLog.log*
   0       0       0 /tmp/myLog.log
 101     909    4839 /tmp/myLog.log.101
 101     909    4839 /tmp/myLog.log.202
  29     261    1382 /tmp/myLog.log.231
 231    2079   11060 total
```

第八章，*进程和信号*，将介绍基于 Unix 信号的日志旋转的更好方法。

# 创建好的随机密码

本节将说明如何在 Go 中创建良好的随机密码，以保护您的 Unix 机器的安全。将其包含在这里的主要原因是，所呈现的 Go 程序将使用您的 Unix 系统定义的`/dev/random`设备来获取随机数生成器的种子。

Go 程序的名称将是`goodPass.go`，它将只需要一个可选参数，即生成的密码的长度：生成的密码的默认大小将为 10 个字符。此外，该程序将生成 ASCII 字符，从`!`到`z`。感叹号的 ASCII 码是 33，而小写 z 的 ASCII 码是 122。

`goodPass.go`的第一部分是必需的序言：

```go
package main 

import ( 
   "encoding/binary" 
   "fmt" 
   "math/rand" 
   "os" 
   "path/filepath" 
   "strconv" 
) 
```

程序的第二部分如下：

```go
var MAX int = 90 
var MIN int = 0 
var seedSize int = 10 

func random(min, max int) int { 
   return rand.Intn(max-min) + min 
} 
```

您已经在第二章中看到了`random()`函数，所以这里没有什么特别有趣的地方。

`goodPass.go`的第三部分是`main()`函数的实现开始的地方：

```go
func main() { 
   if len(os.Args) != 2 { 
         fmt.Printf("usage: %s length\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   LENGTH, _ := strconv.ParseInt(os.Args[1], 10, 64) 
   f, _ := os.Open("/dev/random") 
   var seed int64 
   binary.Read(f, binary.LittleEndian, &seed) 
   rand.Seed(seed) 
   f.Close() 
   fmt.Println("Seed:", seed) 
```

在这里，除了读取命令行参数之外，您还打开了`/dev/random`设备进行读取，这是通过调用`binary.Read()`函数并将读取的内容存储在`seed`变量中实现的。使用`binary.Read()`的原因是您需要指定使用的字节顺序（`binary.LittleEndian`），并且您需要构建一个 int64 而不是一系列字节。这是一个从二进制文件读取到 Go 类型的示例。

程序的最后部分包含以下 Go 代码：

```go
   startChar := "!" 
   var i int64 
   for i = 0; i < LENGTH; i++ { 
         anInt := int(random(MIN, MAX)) 
         newChar := string(startChar[0] + byte(anInt)) 
         if newChar == " " { 
               i = i - i 
               continue 
         } 
         fmt.Print(newChar) 
   } 
   fmt.Println() 
} 
```

正如您所看到的，Go 处理 ASCII 字符的方式很奇怪，因为 Go 默认支持 Unicode 字符。但是，您仍然可以将整数转换为 ASCII 字符，如您在定义`newChar`变量的方式所示。

执行`goodPass.go`将生成以下输出：

```go
$ go run goodPass.go 1
Seed: -5195038511418503382
b
$ go run goodPass.go 10
Seed: 8492864627151568776
k43Ve`+YD)
$ go run goodPass.go 50
Seed: -4276736612056007162
!=Gy+;XV>6eviuR=ST\u:Mk4Q875Y4YZiZhq&q_4Ih/]''`2:x
```

# 另一个 Go 更新

在我写这一章的时候，Go 得到了更新。以下输出显示了相关信息：

```go
$ date
Wed May 24 13:35:36 EEST 2017
$ go version
go version go1.8.2 darwin/amd64 
```

# 练习

1.  查找并阅读`time`包的文档。

1.  尝试更改`userFiles.go`的 Go 代码，以支持多个用户。

1.  更改`insertLineNumber.go`的 Go 代码，以便逐行读取输入文件，将每行写入临时文件，然后用临时文件替换原始文件。如果您不知道如何在哪里创建临时文件，可以使用随机数生成器获取临时文件名和`/tmp`目录进行临时保存。

1.  对`multipleMV.go`进行必要的更改，以便打印与给定正则表达式匹配的文件，而不实际重命名它们。

1.  尝试创建一个匹配`PNG`文件的正则表达式，并使用它来处理日志文件的内容。

1.  创建一个正则表达式，以捕获日期和时间字符串，以便仅打印日期部分并删除时间部分。

# 摘要

在本章中，我们谈到了许多内容，包括处理日志文件，处理 Unix 文件权限，用户和组，创建正则表达式以及处理文本文件。

在下一章中，我们将讨论 Unix 信号，它允许您以异步方式与运行中的程序进行通信。此外，我们将告诉您如何在 Go 中绘图。

f


# 第八章：进程和信号

在上一章中，我们讨论了许多有趣的主题，包括处理 Unix 系统文件，处理 Go 中的日期和时间，查找有关文件权限和用户的信息，以及正则表达式和模式匹配。

本章的核心主题是开发能够处理 Unix 信号的 Go 应用程序。Go 提供了`os/signal`包来处理信号，它使用 Go 通道。尽管通道在下一章中得到了充分的探讨，但这并不妨碍你学习如何在 Go 程序中处理 Unix 信号。

此外，你将学习如何创建可以与 Unix 管道一起工作的 Go 命令行实用程序，如何在 Go 中绘制条形图，以及如何实现`cat(1)`实用程序的 Go 版本。因此，在本章中，你将学习以下主题：

+   列出 Unix 机器的进程

+   Go 中的信号处理

+   Unix 机器支持的信号以及如何使用`kill(1)`命令发送这些信号

+   让信号做你想要的工作

+   在 Go 中实现`cat(1)`实用程序的简单版本

+   在 Go 中绘制数据

+   使用管道将一个程序的输出发送到另一个程序

+   将一个大程序转换为两个较小的程序，它们将通过 Unix 管道协作

+   为 Unix 套接字创建一个客户端

# 关于 Unix 进程和信号

严格来说，**进程**是包含指令、用户数据和系统数据部分以及在运行时获得的其他类型资源的执行环境，而**程序**是一个包含指令和数据的文件，用于初始化进程的指令和用户数据部分。

# 进程管理

总的来说，Go 在处理进程和进程管理方面并不那么擅长。尽管如此，本节将介绍一个小的 Go 程序，通过执行 Unix 命令并获取其输出来列出 Unix 机器的所有进程。程序的名称将是`listProcess.go`。它适用于 Linux 和 macOS 系统，并将分为三个部分。

程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "os/exec" 
   "syscall" 
) 
```

`listProcess.go`的第二部分包含以下 Go 代码：

```go
func main() { 

   PS, err := exec.LookPath("ps") 
   if err != nil { 
         fmt.Println(err) 
   } 
fmt.Println(PS) 

   command := []string{"ps", "-a", "-x"} 
   env := os.Environ() 
   err = syscall.Exec(PS, command, env) 
```

正如你所看到的，你首先需要使用`exec.LookPath()`获取可执行文件的路径，以确保你不会意外地执行另一个二进制文件，然后使用切片定义你想要执行的命令，包括命令的参数。接下来，你将需要使用`os.Environ()`读取 Unix 环境。此外，你可以使用`syscall.Exec()`执行所需的命令，它将自动打印其输出，这并不是一个非常优雅的执行命令的方式，因为你无法控制任务，并且因为你是在最低级别调用进程，而不是使用更高级别的库，比如`os/exec`。

程序的最后一部分是用于打印前面代码的错误消息，如果有的话：

```go
   if err != nil { 
         fmt.Println(err) 
   } 
} 
```

执行`listProcess.go`将生成以下输出：使用`head(1)`实用程序来获取较小的输出：

```go
$ go run listProcess.go | head -3
/bin/ps
  PID TTY           TIME CMD
    1 ??         0:30.72 /sbin/launchd
signal: broken pipe
```

# 关于 Unix 信号

你是否曾经按下*Ctrl* + *C*来停止程序运行？如果是的话，那么你已经熟悉信号，因为*Ctrl* + *C*会向程序发送`SIGINT`信号。

严格来说，Unix**信号**是可以通过名称或数字访问的软件中断，提供了处理异步事件的方式，例如当子进程退出或在 Unix 系统上暂停进程时。

程序无法处理所有信号；其中一些信号是不可捕获和不可忽略的。`SIGKILL`和`SIGSTOP`信号无法被捕获、阻塞或忽略。原因是它们为内核和 root 用户提供了一种停止任何进程的方式。`SIGKILL`信号，也称为数字 9，通常在需要迅速采取行动的极端情况下调用；因此，它通常按数字调用，因为这样做更快。在这里要记住的最重要的事情是，并非所有的 Unix 信号都可以被处理！

# Go 中的 Unix 信号

Go 为程序员提供了`os/signal`包，以帮助他们处理传入的信号。但是，我们将从介绍`kill（1）`实用程序开始讨论处理。

# kill（1）命令

`kill（1）`命令用于终止进程或向其发送一个不那么残酷的信号。请记住，您可以向进程发送信号并不意味着该进程可以或者有代码来处理此信号。

默认情况下，`kill（1）`发送`SIGTERM`信号。如果要查找 Unix 机器支持的所有信号，应执行`kill -l`命令。在 macOS Sierra 机器上，`kill -l`的输出如下：

```go
$ kill -l
1) SIGHUP   2) SIGINT        3) SIGQUIT   4) SIGILL
5) SIGTRAP  6) SIGABRT       7) SIGEMT    8) SIGFPE
9) SIGKILL 10) SIGBUS        11) SIGSEGV 12) SIGSYS
13) SIGPIPE 14) SIGALRM       15) SIGTERM 16) SIGURG
17) SIGSTOP 18) SIGTSTP       19) SIGCONT 20) SIGCHLD
21) SIGTTIN 22) SIGTTOU       23) SIGIO   24) SIGXCPU
25) SIGXFSZ 26) SIGVTALRM     27) SIGPROF 28) SIGWINCH
29) SIGINFO 30) SIGUSR1       31) SIGUSR2
```

如果您在 Debian Linux 机器上执行相同的命令，您将获得更丰富的输出：

```go
$ kill -l
 1) SIGHUP   2) SIGINT   3) SIGQUIT  4) SIGILL   5) SIGTRAP
 6) SIGABRT  7) SIGBUS   8) SIGFPE   9) SIGKILL 10) SIGUSR1
11) SIGSEGV 12) SIGUSR2 13) SIGPIPE 14) SIGALRM 15) SIGTERM
16) SIGSTKFLT     17) SIGCHLD 
18) SIGCONT       19) SIGSTOP 20) SIGTSTP
21) SIGTTIN       22) SIGTTOU 
23) SIGURG        24) SIGXCPU 25) SIGXFSZ
26) SIGVTALRM     27) SIGPROF 28) SIGWINCH 
29) SIGIO         30) SIGPWR
31) SIGSYS        34) SIGRTMIN 
35) SIGRTMIN+1    36) SIGRTMIN+2    37) SIGRTMIN+3
38) SIGRTMIN+4    39) SIGRTMIN+5 
40) SIGRTMIN+6    41) SIGRTMIN+7    42) SIGRTMIN+8
43) SIGRTMIN+9    44) SIGRTMIN+10 
45) SIGRTMIN+11   46) SIGRTMIN+12   47) SIGRTMIN+13
48) SIGRTMIN+14   49) SIGRTMIN+15 
50) SIGRTMAX-14   51) SIGRTMAX-13   52) SIGRTMAX-12
53) SIGRTMAX-11   54) SIGRTMAX-10 
55) SIGRTMAX-9    56) SIGRTMAX-8    57) SIGRTMAX-7
58) SIGRTMAX-6    59) SIGRTMAX-5 
60) SIGRTMAX-4    61) SIGRTMAX-3    62) SIGRTMAX-2
63) SIGRTMAX-1    64) SIGRTMAX
```

如果您尝试杀死或向另一个用户的进程发送另一个信号而没有所需的权限，这很可能会发生，如果您不是*root*用户，`kill（1）`将无法完成任务，并且您将收到类似以下的错误消息：

```go
$ kill 2908
-bash: kill: (2908) - Operation not permitted
```

# Go 中的简单信号处理程序

本小节将介绍一个简单的 Go 程序，仅处理`SIGTERM`和`SIGINT`信号。`h1s.go`的 Go 代码将分为三部分呈现；第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "os/signal" 
   "syscall" 
   "time" 
) 

func handleSignal(signal os.Signal) { 
   fmt.Println("Got", signal) 
} 
```

除了程序的序言之外，还有一个名为`handleSignal（）`的函数，当程序接收到两个支持的信号中的任何一个时，将调用该函数。

`h1s.go`的第二部分包含以下 Go 代码：

```go
func main() { 
   sigs := make(chan os.Signal, 1) 
   signal.Notify(sigs, os.Interrupt, syscall.SIGTERM) 
   go func() { 
         for { 
               sig := <-sigs 
               fmt.Println(sig) 
               handleSignal(sig) 
         } 
   }() 
```

先前的代码使用了**goroutine**和 Go**channel**，这是本书中尚未讨论的 Go 功能。不幸的是，您必须等到第九章*，* *Goroutines - Basic Features*，才能了解更多关于它们的信息。请注意，尽管`os.Interrupt`和`syscall.SIGTERM`属于不同的 Go 包，但它们都是信号。

目前，理解这种技术很重要；它包括三个步骤：

1.  通道的定义，作为传递数据的方式，对于技术（`sigs`）是必需的。

1.  调用`signal.Notify（）`以定义您希望能够捕获的信号列表。

1.  定义一个匿名函数，它在`signal.Notify（）`之后的 goroutine（`go func（）`）中运行，用于决定在收到所需信号时要执行的操作。

在这种情况下，将调用`handleSignal（）`函数。匿名函数内部的`for`循环用于使程序保持处理所有信号，并在接收到第一个信号后不停止。

`h1s.go`的最后部分如下：

```go
   for { 
         fmt.Printf(".") 
         time.Sleep(10 * time.Second) 
   } 
} 
```

这是一个无限的`for`循环，它永远延迟程序的结束：在其位置上，您很可能会放置程序的实际代码。执行`h1s.go`并从另一个终端向其发送信号将使`h1s.go`生成以下输出：

```go
$ ./h1s
......................^Cinterrupt
Got interrupt
^Cinterrupt
Got interrupt
.Hangup: 1
```

这里的坏处是，当接收到`SIGHUP`信号时，`h1s.go`将停止，因为当程序没有专门处理`SIGHUP`时，默认操作是杀死进程！下一小节将展示如何更好地处理三个信号，之后的小节将教您如何处理所有可处理的信号。

# 处理三种不同的信号！

这一小节将教您如何创建一个可以处理三种不同信号的 Go 应用程序：程序的名称将是`h2s.go`，它将处理`SIGTERM`、`SIGINT`和`SIGHUP`信号。

`h2s.go`的 Go 代码将分为四部分呈现。

程序的第一部分包含了预期的序言：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "os/signal" 
   "syscall" 
   "time" 
) 
```

第二部分包含以下 Go 代码：

```go
func handleSignal(signal os.Signal) { 
   fmt.Println("* Got:", signal) 
} 

func main() { 
   sigs := make(chan os.Signal, 1) 
   signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP) 
```

在这里，最后一句告诉您，程序只会处理`os.Interrupt`、`syscall.SIGTERM`和`syscall.SIGHUP`信号。

`h2s.go`的第三部分如下：

```go
   go func() { 
         for { 
               sig := <-sigs 
               switch sig { 
               case os.Interrupt: 
                     handleSignal(sig) 
               case syscall.SIGTERM: 
                     handleSignal(sig) 
               case syscall.SIGHUP: 
                     fmt.Println("Got:", sig) 
                     os.Exit(-1) 
               } 
         } 
   }() 
```

在这里，您可以看到，当捕获到特定信号时，不一定要调用单独的函数；也可以在`for`循环内处理它，就像`syscall.SIGHUP`一样。但是，我认为使用命名函数更好，因为它使 Go 代码更易于阅读和修改。好处是 Go 有一个处理所有信号的中心位置，这使得很容易找出程序的运行情况。

此外，`h2s.go`专门处理`SIGHUP`信号，尽管`SIGHUP`信号仍将终止程序；但是，这次是我们的决定。

请记住，通常最好让一个信号处理程序来停止程序，否则您将不得不通过发出`kill -9`命令来终止它。

`h2s.go`的最后一部分如下：

```go
   for { 
         fmt.Printf(".") 
         time.Sleep(10 * time.Second) 
   } 
}
```

执行`h2s.go`并从另一个 shell 发送四个信号（`SIGINT`、`SIGTERM`、`SIGHUP`和`SIGKILL`）给它将生成以下输出：

```go
$ go build h2s.go
$ ./h2s
..* Got: interrupt
* Got: terminated
.Got: hangup
.Killed: 9
```

构建`h2s.go`的原因是更容易找到自主程序的进程 ID：`go run`命令在后台构建了一个临时可执行程序，这种情况下提供的灵活性较少。如果要改进`h2s.go`，可以让它调用`os.Getpid()`来打印其进程 ID，这样就不必自己查找了。

程序在收到无法处理的`SIGKILL`信号之前处理了三个信号，因此终止了！

# 捕获每个可以处理的信号

这一小节将介绍一种简单的技术，允许您捕捉每个可以处理的信号：再次强调，您不能处理所有信号！程序将在收到`SIGTERM`信号后停止运行。

程序的名称将是`catchAll.go`，将分为三部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "os/signal" 
   "syscall" 
   "time" 
) 

func handleSignal(signal os.Signal) { 
   fmt.Println("* Got:", signal) 
} 
```

程序的第二部分如下：

```go
func main() { 
   sigs := make(chan os.Signal, 1) 
   signal.Notify(sigs) 
   go func() { 
         for { 
               sig := <-sigs 
               switch sig { 
               case os.Interrupt: 
                     handleSignal(sig) 
               case syscall.SIGTERM: 
                     handleSignal(sig) 
                     os.Exit(-1) 
               case syscall.SIGUSR1: 
                     handleSignal(sig) 
               default: 
                     fmt.Println("Ignoring:", sig) 
               } 
         } 
   }() 
```

在这种情况下，调用`signal.Notify()`的方式对您的代码产生了影响。如果您没有定义任何特定的信号，程序将能够处理任何可以处理的信号。但是，匿名函数内的`for`循环只处理了三个信号，而忽略了其余的！请注意，我认为这是在 Go 中处理信号的最佳方式：捕获一切，同时只处理您感兴趣的信号。但是，有些人认为明确处理您处理的内容是更好的方法。这里没有对错之分。

`catchAll.go`程序在收到`SIGHUP`时不会终止，因为`switch`块的`default`情况处理了它。

最后一部分是对`time.Sleep()`函数的预期调用：

```go
   for { 
         fmt.Printf(".") 
         time.Sleep(10 * time.Second) 
   } 
} 
```

执行`catchAll.go`将产生以下输出：

```go
$ ./catchAll
.Ignoring: hangup
.......................................* Got: interrupt
* Got: user defined signal 1
.Ignoring: user defined signal 2
Ignoring: hangup
.* Got: terminated
$
```

# 重新审视旋转日志文件！

正如我在第七章中告诉过您，本章将向您介绍一种技术，可以让您以更常规的方式结束程序并旋转日志文件，这是通过信号和信号处理来实现的。

`rotateLog.go`的新版本名称将是`rotateSignals.go`，将分为四个部分呈现。此外，当实用程序接收`os.Interrupt`时，它将旋转当前日志文件，而当它接收`syscall.SIGTERM`时，它将终止执行。可以处理的任何其他信号都将创建一个日志条目，而不会执行其他操作。

`rotateSignals.go`的第一部分是预期的序言：

```go
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
   "os/signal" 
   "strconv" 
   "syscall" 
   "time" 
) 

var TOTALWRITES int = 0 
var openLogFile os.File 
```

`rotateSignals.go`的第二部分包含以下 Go 代码：

```go
func rotateLogFile(filename string) error { 
   openLogFile.Close() 
   os.Rename(filename, filename+"."+strconv.Itoa(TOTALWRITES)) 
   err := setUpLogFile(filename) 
   return err 
} 

func setUpLogFile(filename string) error { 
   openLogFile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644) 
   if err != nil { 
         return err 
   } 
   log.SetOutput(openLogFile) 
   return nil 
} 
```

您刚刚在这里定义了两个执行两项任务的函数。`rotateSignals.go`的第三部分包含以下 Go 代码：

```go
func main() { 
   filename := "/tmp/myLog.log" 
   err := setUpLogFile(filename) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(-1) 
   } 

   sigs := make(chan os.Signal, 1) 
   signal.Notify(sigs) 
```

再次，所有信号都将被捕获。`rotateSignals.go`的最后一部分如下：

```go
   go func() { 
         for { 
               sig := <-sigs 
               switch sig { 
               case os.Interrupt: 
                     rotateLogFile(filename) 
                     TOTALWRITES++ 
               case syscall.SIGTERM: 
                     log.Println("Got:", sig) 
                     openLogFile.Close() 
                     TOTALWRITES++ 
                     fmt.Println("Wrote", TOTALWRITES, "log entries in total!") 
                     os.Exit(-1) 
               default: 
                     log.Println("Got:", sig) 
                     TOTALWRITES++ 
               } 
         } 
   }() 

   for { 
         time.Sleep(10 * time.Second) 
   } 
} 
```

正如您所看到的，`rotateSignals.go`通过为每个信号编写一个日志条目记录了它接收到的信号的信息。虽然呈现`rotateSignals.go`的整个代码是不错的，但是看到`diff(1)`实用程序的输出以显示`rotateLog.go`和`rotateSignals.go`之间的代码差异将是非常有教育意义的：

```go
$ diff rotateLog.go rotateSignals.go
6a7
>     "os/signal"
7a9
>     "syscall"
12,13d13
< var ENTRIESPERLOGFILE int = 100
< var WHENTOSTOP int = 230
33d32
<     numberOfLogEntries := 0
41,51c40,59
<     for {
<           log.Println(numberOfLogEntries, "This is a test log entry")
<           numberOfLogEntries++
<           TOTALWRITES++
<           if numberOfLogEntries > ENTRIESPERLOGFILE {
<                 _ = rotateLogFile(filename)
<                 numberOfLogEntries = 0
<           }
<           if TOTALWRITES > WHENTOSTOP {
<                 _ = rotateLogFile(filename)
<                 break
---
>     sigs := make(chan os.Signal, 1)
>     signal.Notify(sigs)
>
>     go func() {
>           for {
>                 sig := <-sigs
>                 switch sig {
>                 case os.Interrupt:
>                       rotateLogFile(filename)
>                       TOTALWRITES++
>                 case syscall.SIGTERM:
>                       log.Println("Got:", sig)
>                       openLogFile.Close()
>                       TOTALWRITES++
>                       fmt.Println("Wrote", TOTALWRITES, "log entries in total!")
>                       os.Exit(-1)
>                 default:
>                       log.Println("Got:", sig)
>                       TOTALWRITES++
>                 }
53c61,64
<           time.Sleep(time.Second)
---
>     }()
>
>     for {
>           time.Sleep(10 * time.Second)
55d65
<     fmt.Println("Wrote", TOTALWRITES, "log entries!")
```

这里的好处是，在`rotateSignals.go`中使用信号使得`rotateLog.go`中使用的大多数全局变量变得不必要，因为现在您可以通过发送信号来控制实用程序。此外，`rotateSignals.go`的设计和结构比`rotateLog.go`更简单，因为您只需要理解匿名函数的功能。

执行`rotateSignals.go`并向其发送一些信号后，`/tmp/myLog.log`的内容将如下所示：

```go
$ cat /tmp/myLog.log
2017/06/03 14:53:33 Got: user defined signal 1
2017/06/03 14:54:08 Got: user defined signal 1
2017/06/03 14:54:12 Got: user defined signal 2
2017/06/03 14:54:19 Got: terminated
```

此外，您将在`/tmp`目录下有以下文件：

```go
$ ls -l /tmp/myLog.log*
-rw-r--r--  1 mtsouk  wheel  177 Jun  3 14:54 /tmp/myLog.log
-rw-r--r--  1 mtsouk  wheel  106 Jun  3 13:42 /tmp/myLog.log.0
```

# 改进文件复制

当`cp(1)`实用程序接收`SIGINFO`信号时，它会打印有用的信息，如下所示：

```go
$ cp FileToCopy /tmp/copy
FileToCopy -> /tmp/copy  26%
FileToCopy -> /tmp/copy  29%
FileToCopy -> /tmp/copy  31%
```

因此，本节的其余部分将为`cp(1)`命令的 Go 实现实现相同的功能。本节中的 Go 代码将基于`cp.go`程序，因为当使用较小的缓冲区大小时，它可能非常慢，从而为我们提供测试时间。新的复制实用程序的名称将是`cpSignal.go`，将分为四个部分呈现。

`cpSignal.go`和`cp.go`之间的基本区别在于`cpSignal.go`应该找到输入文件的大小，并在给定点保持已写入的字节数。除了这些修改之外，您不必担心其他任何事情，因为两个版本的核心功能，即复制文件，完全相同。

程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "io" 
   "os" 
   "os/signal" 
   "path/filepath" 
   "strconv" 
   "syscall" 
) 

var BUFFERSIZE int64 
var FILESIZE int64 
var BYTESWRITTEN int64 
```

为了使开发人员更容易，程序引入了两个名为`FILESIZE`和`BYTESWRITTEN`的全局变量，它们分别保持输入文件的大小和已写入的字节数。这两个变量都被处理`SIGINFO`信号的函数使用。

第二部分如下：

```go
func Copy(src, dst string, BUFFERSIZE int64) error { 
   sourceFileStat, err := os.Stat(src) 
   if err != nil { 
         return err 
   } 

   FILESIZE = sourceFileStat.Size() 

   if !sourceFileStat.Mode().IsRegular() { 
         return fmt.Errorf("%s is not a regular file.", src) 
   } 

   source, err := os.Open(src) 
   if err != nil { 
         return err 
   } 
   defer source.Close() 

   _, err = os.Stat(dst) 
   if err == nil { 
         return fmt.Errorf("File %s already exists.", dst) 
   } 

   destination, err := os.Create(dst) 
   if err != nil { 
         return err 
   } 
   defer destination.Close() 

   if err != nil { 
         panic(err) 
   } 

   buf := make([]byte, BUFFERSIZE) 
   for { 
         n, err := source.Read(buf) 
         if err != nil && err != io.EOF { 
               return err 
         } 
         if n == 0 { 
               break 
         } 
         if _, err := destination.Write(buf[:n]); err != nil { 
               return err 
         } 
         BYTESWRITTEN = BYTESWRITTEN + int64(n) 
   } 
   return err 
} 
```

在这里，您使用`sourceFileStat.Size()`函数获取输入文件的大小，并设置`FILESIZE`全局变量的值。

第三部分是您定义信号处理的地方：

```go
func progressInfo() { 
   progress := float64(BYTESWRITTEN) / float64(FILESIZE) * 100 
   fmt.Printf("Progress: %.2f%%\n", progress) 
} 

func main() { 
   if len(os.Args) != 4 { 
         fmt.Printf("usage: %s source destination BUFFERSIZE\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   source := os.Args[1] 
   destination := os.Args[2] 
   BUFFERSIZE, _ = strconv.ParseInt(os.Args[3], 10, 64) 
   BYTESWRITTEN = 0 

   sigs := make(chan os.Signal, 1) 
   signal.Notify(sigs) 
```

在这里，您选择捕获所有信号。但是，匿名函数的 Go 代码只会在接收到`syscall.SIGINFO`信号后调用`progressInfo()`。

如果您想要一种优雅地终止程序的方法，您可能希望使用`SIGINT`信号，因为当捕获所有信号时，优雅地终止程序将不再可能：您将需要发送`SIGKILL`来终止程序，这有点残酷。

`cpSignal.go`的最后一部分如下：

```go
   go func() { 
         for {
               sig := <-sigs 
               switch sig { 
               case syscall.SIGINFO:
                     progressInfo() 
               default: 
                     fmt.Println("Ignored:", sig) 
               } 
         } 
   }() 

   fmt.Printf("Copying %s to %s\n", source, destination) 
   err := Copy(source, destination, BUFFERSIZE) 
   if err != nil { 
         fmt.Printf("File copying failed: %q\n", err) 
   } 
} 
```

执行`cpSignal.go`并向其发送两个`SIGINFO`信号将生成以下输出：

```go
$ ./cpSignal FileToCopy /tmp/copy 2
Copying FileToCopy to /tmp/copy
Ignored: user defined signal 1
Progress: 21.83%
^CIgnored: interrupt
Progress: 29.78%
```

# 绘制数据

本节将开发一个实用程序，它将读取多个日志文件，并将创建一个图像，其中每个条将表示在日志文件中找到给定 IP 地址的次数。

然而，Unix 哲学告诉我们，我们应该制作两个不同的实用程序，而不是开发一个单一的实用程序：一个用于处理日志文件并创建报告，另一个用于绘制第一个实用程序生成的数据：这两个实用程序将使用 Unix 管道进行通信。尽管本节将实现第一种方法，但您将在本章的*The * `plotIP.go` *utility revisited*部分中看到第二种方法的实现。

所提供实用程序的想法来自我为一本杂志撰写的教程，我在其中开发了一个小型的 Go 程序进行绘图：即使是小型和天真的程序也可以激发您开发更大的东西，因此不要低估它们的力量。

实用程序的名称将是`plotIP.go`，并且将分为七个部分：好处是`plotIP.go`将重用`countIP.go`和`findIP.go`的一些代码。`plotIP.go`唯一不做的事情就是将文本写入图像，因此您只能绘制条形图，而不知道实际值或特定条形图的相应日志文件：您可以尝试将文本功能添加到程序中作为练习。

此外，`plotIP.go`将需要至少三个参数，即图像的宽度和高度以及将要使用的日志文件的名称：为了使`plotIP.go`更小，`plotIP.go`将不使用`flag`包，并假定您将按正确的顺序提供其参数。如果您提供更多的参数，它将把它们视为日志文件。

`plotIP.go`的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "image" 
   "image/color" 
   "image/png" 
   "io" 
   "os" 
   "path/filepath" 
   "regexp" 
   "strconv" 
) 

var m *image.NRGBA
var x int 
var y int 
var barWidth int 
```

这些全局变量与图像的尺寸（`x`和`y`）、图像作为 Go 变量（`m`）以及其中一个条形图的宽度（`barWidth`）有关，该宽度取决于图像的大小和将要绘制的条形图的数量。请注意，在这里使用`x`和`y`作为变量名而不是像`IMAGEWIDTH`和`IMAGEHEIGHT`之类的名称可能有点错误和危险。

第二部分是以下内容：

```go
func findIP(input string) string { 
   partIP := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])" 
   grammar := partIP + "\\." + partIP + "\\." + partIP + "\\." + partIP 
   matchMe := regexp.MustCompile(grammar) 
   return matchMe.FindString(input) 
} 

func plotBar(width int, height int, color color.RGBA) { 
   xx := 0
   for xx < barWidth { 
         yy := 0 
         for yy < height { 
               m.Set(xx+width, y-yy, color) 
               yy = yy + 1 
         } 
         xx = xx + 1 
   } 
} 
```

在这里，您实现了一个名为`plotBar()`的 Go 函数，该函数根据条形图的高度、宽度和颜色进行绘制。这个函数是`plotIP.go`中最具挑战性的部分。

第三部分包含以下 Go 代码：

```go
func getColor(x int) color.RGBA { 
   switch {

   case x == 0: 
         return color.RGBA{0, 0, 255, 255} 
   case x == 1: 
         return color.RGBA{255, 0, 0, 255} 
   case x == 2: 
         return color.RGBA{0, 255, 0, 255} 
   case x == 3: 
         return color.RGBA{255, 255, 0, 255} 
   case x == 4: 
         return color.RGBA{255, 0, 255, 255} 
   case x == 5: 
         return color.RGBA{0, 255, 255, 255} 
   case x == 6: 
         return color.RGBA{255, 100, 100, 255} 
   case x == 7: 
         return color.RGBA{100, 100, 255, 255} 
   case x == 8: 
         return color.RGBA{100, 255, 255, 255} 
   case x == 9: 
         return color.RGBA{255, 255, 255, 255} 
   } 
   return color.RGBA{0, 0, 0, 255} 
} 
```

此函数允许您定义输出中将出现的颜色：如果需要，可以更改它们。

第四部分包含以下 Go 代码：

```go
func main() { 
   var data []int 
   arguments := os.Args 
   if len(arguments) < 4 { 
         fmt.Printf("%s X Y IP input\n", filepath.Base(arguments[0])) 
         os.Exit(0) 
   } 

   x, _ = strconv.Atoi(arguments[1]) 
   y, _ = strconv.Atoi(arguments[2]) 
   WANTED := arguments[3] 
   fmt.Println("Image size:", x, y) 
```

在这里，您可以读取所需的 IP 地址，该地址保存在`WANTED`变量中，并读取生成的 PNG 图像的尺寸。

第五部分包含以下 Go 代码：

```go
   for _, filename := range arguments[4:] { 
         count := 0 
         fmt.Println(filename) 
         f, err := os.Open(filename) 
         if err != nil { 
               fmt.Fprintf(os.Stderr, "Error: %s\n", err) 
               continue 
         } 
         defer f.Close() 

         r := bufio.NewReader(f) 
         for { 
               line, err := r.ReadString('\n') 
               if err == io.EOF { 
                     break 
               } 

if err != nil { 
                fmt.Fprintf(os.Stderr, "Error in file: %s\n", err) 
                     continue 
               } 
               ip := findIP(line) 
               if ip == WANTED { 
                     count++

               } 
         } 
         data = append(data, count) 
   } 
```

在这里，您逐个处理输入的日志文件，并将计算的值存储在`data`切片中。错误消息将打印到`os.Stderr`：从将错误消息打印到`os.Stderr`中获得的主要优势是，您可以轻松地将错误消息重定向到文件，同时以不同的方式使用写入到`os.Stdout`的数据。

`plotIP.go`的第六部分包含以下 Go 代码：

```go
   fmt.Println("Slice length:", len(data)) 
   if len(data)*2 > x { 
         fmt.Println("Image size (x) too small!") 
         os.Exit(-1) 
   } 

   maxValue := data[0] 
   for _, temp := range data { 
         if maxValue < temp { 
               maxValue = temp 
         } 
   } 

   if maxValue > y { 
         fmt.Println("Image size (y) too small!") 
         os.Exit(-1) 
   } 
   fmt.Println("maxValue:", maxValue) 
   barHeighPerUnit := int(y / maxValue) 
   fmt.Println("barHeighPerUnit:", barHeighPerUnit) 
   PNGfile := WANTED + ".png" 
   OUTPUT, err := os.OpenFile(PNGfile, os.O_CREATE|os.O_WRONLY, 0644) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(-1) 
   } 
   m = image.NewNRGBA(image.Rectangle{Min: image.Point{0, 0}, Max: image.Point{x, y}}) 
```

在这里，您可以计算有关绘图的事项，并使用`os.OpenFile()`创建输出图像文件。由`plotIP.go`实用程序生成的 PNG 文件以给定的 IP 地址命名，以使事情变得更简单。

`plotIP.go`的 Go 代码的最后一部分如下：

```go
   i := 0 
   barWidth = int(x / len(data)) 
   fmt.Println("barWidth:", barWidth) 
   for _, v := range data { 
         c := getColor(v % 10) 
         yy := v * barHeighPerUnit 
         plotBar(barWidth*i, yy, c) 
         fmt.Println("plotBar", barWidth*i, yy) 
         i = i + 1 
   } 
   png.Encode(OUTPUT, m) 
} 
```

在这里，您可以读取`data`切片的值，并通过调用`plotBar()`函数为每个值创建一个条形图。

执行`plotIP.go`将生成以下输出：

```go
$ go run plotIP.go 1300 1500 127.0.0.1 /tmp/log.*
Image size: 1300 1500
/tmp/log.1
/tmp/log.2
/tmp/log.3
Slice length: 3
maxValue: 1500
barHeighPerUnit: 1
barWidth: 433
plotBar 0 1500
plotBar 433 1228
plotBar 866 532
$  ls -l 127.0.0.1.png
-rw-r--r-- 1 mtsouk mtsouk 11023 Jun  5 18:36 127.0.0.1.png
```

然而，除了生成的文本输出之外，重要的是生成的 PNG 文件，可以在以下图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/0705a55e-044d-4918-bfea-70d6b7d9377e.png)

由 plotIP.go 实用程序生成的输出

如果要将错误消息保存到不同的文件中，可以使用以下命令的变体：

```go
$ go run plotIP.go 130 150 127.0.0.1 doNOTExist 2> err
Image size: 130 150
doNOTExist
Slice length: 0
$ cat err
Error: open doNOTExist: no such file or directory
panic: runtime error: index out of range

goroutine 1 [running]:
main.main()
     /Users/mtsouk/Desktop/goBook/ch/ch8/code/plotIP.go:112 +0x12de
exit status 2
```

以下命令通过将其发送到`/dev/null`来丢弃所有错误消息：

```go
$ go run plotIP.go 1300 1500 127.0.0.1 doNOTExist 2>/dev/null
Image size: 1300 1500
doNOTExist
Slice length: 0  
```

# 在 Go 中的 Unix 管道

我们在第六章*，*文件输入和输出中首次讨论了管道。管道有两个严重的限制：首先，它们通常是单向通信的，其次，它们只能在具有共同祖先的进程之间使用。

管道背后的一般思想是，如果您没有要处理的文件，应该等待从标准输入获取输入。同样，如果没有要求将输出保存到文件，应该将输出写入标准输出，供用户查看或供其他程序处理。因此，管道可用于在两个进程之间流式传输数据，而不创建任何临时文件。

本节将呈现一些使用 Unix 管道编写的简单实用程序，以增加清晰度。

# 从标准输入读取

为了开发支持 Unix 管道的 Go 应用程序，您需要知道如何从标准输入读取。

开发的程序名为`readSTDIN.go`，将分为三部分呈现。

程序的第一部分是预期的序言：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "os" 
) 
```

`readSTDIN.go`的第二部分包含以下 Go 代码：

```go
func main() { 
   filename := "" 
   var f *os.File 
   arguments := os.Args 
   if len(arguments) == 1 { 
         f = os.Stdin 
   } else { 
         filename = arguments[1] 
         fileHandler, err := os.Open(filename) 
         if err != nil { 
               fmt.Printf("error opening %s: %s", filename, err) 
               os.Exit(1) 
         } 
         f = fileHandler 
   } 
   defer f.Close() 
```

在这里，您可以确定是否有实际文件要处理，这可以通过程序的命令行参数数量来确定。如果没有要处理的文件，您将尝试从`os.Stdin`读取数据。确保您理解所呈现的技术，因为在本章中将多次使用它。

`readSTDIN.go`的最后一部分如下：

```go
   scanner := bufio.NewScanner(f) 
   for scanner.Scan() { 
         fmt.Println(">", scanner.Text()) 
   } 
} 
```

这段代码无论是处理实际文件还是`os.Stdin`都是一样的，这是因为在 Unix 中一切都是文件。请注意，程序输出以`>`字符开头。

执行`readSTDIN.go`将生成以下输出：

```go
$ cat /tmp/testfile
1
2
$ go run readSTDIN.go /tmp/testFile
> 1
> 2
$ cat /tmp/testFile | go run readSTDIN.go
> 1
> 2
$ go run readSTDIN.go
3
> 3
2
> 2
1
> 1
```

在最后一种情况下，`readSTDIN.go`会回显它读取的每一行，因为输入是逐行读取的：`cat(1)`实用程序的工作方式相同。

# 将数据发送到标准输出

本小节将向您展示如何以比仅使用`fmt.Println()`或`fmt`标准 Go 包中的任何其他函数更好的方式将数据发送到标准输出。Go 程序将被命名为`writeSTDOUT.go`，并将分为三部分呈现给您。

第一部分如下：

```go
package main 

import ( 
   "io" 
   "os" 
) 
```

`writeSTDOUT.go`的第二部分包含以下 Go 代码：

```go
func main() { 
   myString := "" 
   arguments := os.Args 
   if len(arguments) == 1 { 
         myString = "You did not give an argument!" 
   } else { 
         myString = arguments[1] 
   } 
```

`writeSTDOUT.go`的最后一部分如下：

```go
   io.WriteString(os.Stdout, myString) 
   io.WriteString(os.Stdout, "\n") 
} 
```

唯一微妙的是，在使用`io.WriteString()`将数据写入`os.Stdout`之前，您需要将文本放入一个切片中。

执行`writeSTDOUT.go`将生成以下输出：

```go
$ go run writeSTDOUT.go 123456
123456
$ go run writeSTDOUT.go
You do not give an argument!
```

# 在 Go 中实现 cat(1)

本小节将呈现`cat(1)`命令行实用程序的 Go 版本。如果您向`cat(1)`提供一个或多个命令行参数，那么`cat(1)`将在屏幕上打印它们的内容。但是，如果您只在 Unix shell 中键入`cat(1)`，那么`cat(1)`将等待您的输入，当您键入*Ctrl* + *D*时输入将终止。

Go 实现的名称将是`cat.go`，将分为三部分呈现。

`cat.go`的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "os" 
) 
```

第二部分如下：

```go
func catFile(filename string) error { 
   f, err := os.Open(filename) 
   if err != nil { 
         return err 
   } 
   defer f.Close() 
   scanner := bufio.NewScanner(f) 
   for scanner.Scan() { 
         fmt.Println(scanner.Text()) 
   } 
   return nil 
} 
```

当`cat.go`实用程序需要处理真实文件时，将调用`catFile()`函数。有一个函数来完成您的工作可以使程序设计更好。

最后一部分包含以下 Go 代码：

```go
func main() { 
   filename := "" 
   arguments := os.Args 
   if len(arguments) == 1 { 
         io.Copy(os.Stdout, os.Stdin) 
         os.Exit(0) 
   } 

   filename = arguments[1] 
   err := catFile(filename) 
   if err != nil { 
         fmt.Println(err) 
   } 
} 
```

因此，如果程序没有参数，则假定它必须从`os.Stdin`读取。在这种情况下，它只会回显您给它的每一行。如果程序有参数，则它将使用`catFile()`函数处理第一个参数作为文件。

执行`cat.go`将生成以下输出：

```go
$ go run cat.go /tmp/testFile  |  go run cat.go
1
2
$ go run cat.go
Mihalis
Mihalis
Tsoukalos
Tsoukalos $ echo "Mihalis Tsoukalos" | go run cat.go
Mihalis Tsoukalos
```

# 重新审视 plotIP.go 实用程序

正如本章的前一节所承诺的，本节将创建两个单独的实用程序，结合起来将实现`plotIP.go`的功能。个人而言，我更喜欢有两个单独的实用程序，并在需要时将它们结合起来，而不是只有一个实用程序可以执行两个或更多任务。

这两个实用程序的名称将是`extractData.go`和`plotData.go`。正如您可以轻松理解的那样，只有第二个实用程序才能够从标准输入获取输入，只要第一个实用程序将其输出打印在标准输出上，要么使用`os.Stdout`，这是正确的方式，要么使用`fmt.Println()`，通常可以完成任务。

我认为我现在应该告诉您我的小秘密：我首先创建了`extractData.go`和`plotData.go`，然后开发了`plotIP.go`，因为开发两个单独的实用程序比开发一个做所有事情的大型实用程序更容易！此外，使用两个不同的实用程序允许您使用标准 Unix 实用程序（如`tail(1)`、`sort(1)`和`head(1)`）过滤`extractData.go`的输出，这意味着您可以以不同的方式修改数据，而无需编写任何额外的 Go 代码。

将两个命令行实用程序并创建一个实用程序来实现这两个实用程序的功能要比将一个大型实用程序分割成两个或更多不同实用程序的功能更容易，因为后者通常需要更多的变量和更多的错误检查。

`extractData.go`实用程序将分为四个部分；第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "os" 
   "path/filepath" 
   "regexp" 
) 
```

`extractData.go`的第二部分包含以下 Go 代码：

```go
func findIP(input string) string { 
   partIP := "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])" 
   grammar := partIP + "\\." + partIP + "\\." + partIP + "\\." + partIP 
   matchMe := regexp.MustCompile(grammar) 
   return matchMe.FindString(input) 
} 
```

您应该熟悉`findIP()`函数，您在第七章中看到了`findIP.go`。

`extractData.go`的第三部分如下：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) < 3 { 
         fmt.Printf("%s IP <files>\n", filepath.Base(os.Args[0])) 
         os.Exit(-1) 
   } 

   WANTED := arguments[1] 
   for _, filename := range arguments[2:] { 
         count := 0 
         buf := []byte(filename)
         io.WriteString(os.Stdout, string(buf)) 
         f, err := os.Open(filename) 
         if err != nil { 
               fmt.Fprintf(os.Stderr, "Error: %s\n", err) 
               continue 
         } 
         defer f.Close() 
```

这里使用`buf`变量是多余的，因为`filename`是一个字符串，`io.WriteString()`期望一个字符串：这只是我的习惯，将`filename`的值放入字节片中。如果您愿意，可以将其删除。

再次，大部分 Go 代码来自`plotIP.go`实用程序。`extractData.go`的最后一部分如下：

```go
         r := bufio.NewReader(f) 
         for { 
               line, err := r.ReadString('\n') 
               if err == io.EOF { 
                     break 
               } else if err != nil { 
                     fmt.Fprintf(os.Stderr, "Error in file: %s\n", err) 
                     continue 
               } 

               ip := findIP(line) 
               if ip == WANTED { 
                     count = count + 1 
               } 
         } 
         buf = []byte(strconv.Itoa(count))
         io.WriteString(os.Stdout, " ") 
         io.WriteString(os.Stdout, string(buf)) 
         io.WriteString(os.Stdout, "\n") 
   } 
} 
```

在这里，`extractData.go`将其输出写入标准输出（`os.Stdout`），而不是使用`fmt`包的函数，以便更兼容管道。`extractData.go`实用程序至少需要两个参数：IP 地址和日志文件，但它可以处理任意数量的日志文件。

您可能希望将第三部分中的`filename`值的打印移至此处，以便将所有打印命令放在同一位置。

执行`extractData.go`将生成以下输出：

```go
$ ./extractData 127.0.0.1 access.log{,.1}
access.log 3099
access.log.1 6333
```

虽然`extractData.go`在每行打印两个值，但`plotData.go`只会使用第二个字段。最好的方法是使用`awk(1)`过滤`extractData.go`的输出：

```go
$ ./extractData 127.0.0.1 access.log{,.1} | awk '{print $2}'
3099
6333
```

正如您所理解的，`awk(1)`允许您对生成的值进行更多操作。

`plotData.go`实用程序也将分为六个部分；它的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "image" 
   "image/color" 
   "image/png" 
   "os" 
   "path/filepath" 
   "strconv" 
) 

var m *image.NRGBA 
var x int 
var y int 
var barWidth int 
```

再次，使用全局变量是为了避免向实用程序的某些函数传递太多参数。

`plotData.go`的第二部分包含以下 Go 代码：

```go
func plotBar(width int, height int, color color.RGBA) { 
   xx := 0
   for xx < barWidth { 
         yy := 0 
         for yy < height { 
               m.Set(xx+width, y-yy, color) 
               yy = yy + 1 
         } 
         xx = xx + 1 
   } 
} 
```

`plotData.go`的第三部分包含以下 Go 代码：

```go
func getColor(x int) color.RGBA { 
   switch {
   case x == 0: 
         return color.RGBA{0, 0, 255, 255} 
   case x == 1: 
         return color.RGBA{255, 0, 0, 255} 
   case x == 2: 
         return color.RGBA{0, 255, 0, 255} 
   case x == 3: 
         return color.RGBA{255, 255, 0, 255} 
   case x == 4: 
         return color.RGBA{255, 0, 255, 255} 
   case x == 5: 
         return color.RGBA{0, 255, 255, 255} 
   case x == 6: 
         return color.RGBA{255, 100, 100, 255} 
   case x == 7: 
         return color.RGBA{100, 100, 255, 255} 
   case x == 8: 
         return color.RGBA{100, 255, 255, 255} 
   case x == 9: 
         return color.RGBA{255, 255, 255, 255} 
   } 
   return color.RGBA{0, 0, 0, 255} 
} 
```

`plotData.go`的第四部分包含以下 Go 代码：

```go
func main() { 
   var data []int 
   var f *os.File 
   arguments := os.Args 
   if len(arguments) < 3 { 
         fmt.Printf("%s X Y input\n", filepath.Base(arguments[0])) 
         os.Exit(0) 
   } 

   if len(arguments) == 3 { 
         f = os.Stdin 
   } else { 
         filename := arguments[3] 
         fTemp, err := os.Open(filename) 
         if err != nil { 
               fmt.Println(err) 
               os.Exit(0) 
         } 
         f = fTemp 
   } 
   defer f.Close() 

   x, _ = strconv.Atoi(arguments[1]) 
   y, _ = strconv.Atoi(arguments[2]) 
   fmt.Println("Image size:", x, y) 
```

`plotData.go`的第五部分如下：

```go
   scanner := bufio.NewScanner(f) 
   for scanner.Scan() { 
         value, err := strconv.Atoi(scanner.Text()) 
         if err == nil { 
               data = append(data, value) 
         } else { 
               fmt.Println("Error:", value) 
         } 
   } 

   fmt.Println("Slice length:", len(data)) 
   if len(data)*2 > x { 
         fmt.Println("Image size (x) too small!") 
         os.Exit(-1) 
   } 

   maxValue := data[0] 
   for _, temp := range data { 
         if maxValue < temp { 
               maxValue = temp 
         } 
   } 

   if maxValue > y { 
         fmt.Println("Image size (y) too small!") 
         os.Exit(-1) 
   } 
   fmt.Println("maxValue:", maxValue) 
   barHeighPerUnit := int(y / maxValue) 
   fmt.Println("barHeighPerUnit:", barHeighPerUnit) 
```

`plotData.go`的最后一部分如下：

```go
   PNGfile := arguments[1] + "x" + arguments[2] + ".png" 
   OUTPUT, err := os.OpenFile(PNGfile, os.O_CREATE|os.O_WRONLY, 0644) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(-1) 
   } 
   m = image.NewNRGBA(image.Rectangle{Min: image.Point{0, 0}, Max: image.Point{x, y}}) 

   i := 0 
   barWidth = int(x / len(data)) 
   fmt.Println("barWidth:", barWidth) 
   for _, v := range data { 
         c := getColor(v % 10) 
         yy := v * barHeighPerUnit 
         plotBar(barWidth*i, yy, c) 
         fmt.Println("plotBar", barWidth*i, yy) 
         i = i + 1 
   } 

   png.Encode(OUTPUT, m) 
} 
```

虽然您可以单独使用`plotData.go`，但使用`extractData.go`的输出作为`plotData.go`的输入就像执行以下命令一样简单：

```go
$ ./extractData.go 127.0.0.1 access.log{,.1} | awk '{print $2}' | ./plotData 6000 6500
Image size: 6000 6500
Slice length: 2
maxValue: 6333
barHeighPerUnit: 1
barWidth: 3000
plotBar 0 3129
plotBar 3000 6333
$ ls -l 6000x6500.png
-rw-r--r-- 1 mtsouk mtsouk 164915 Jun  5 18:25 6000x6500.png
```

前一个命令的图形输出可以是一个图像，就像您在以下图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/ee09e9bd-e219-47d1-98f4-47de7bc75848.png)

plotData.go 实用程序生成的输出

# 在 Go 中使用 Unix 套接字

存在两种类型的套接字：Unix 套接字和网络套接字。网络套接字将在第十二章，*网络编程*中解释，而 Unix 套接字将在本节中简要解释。然而，由于所呈现的 Go 函数也适用于 TCP/IP 套接字，因此您仍需等待第十二章，*网络编程*，以充分理解它们，因为它们在这里不会被解释。因此，本节将仅呈现 Unix 套接字客户端的 Go 代码，这是一个使用 Unix 套接字（一种特殊的 Unix 文件）来读取和写入数据的程序。该程序的名称将是`readUNIX.go`，将分为三部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "io" 
   "net" 
   "strconv" 
   "time" 
) 
```

`readUNIX.go`的第二部分如下：

```go
func readSocket(r io.Reader) { 
   buf := make([]byte, 1024) 
   for { 
         n, _ := r.Read(buf[:]) 
         fmt.Print("Read: ", string(buf[0:n])) 
   } 
} 
```

最后一部分包含以下 Go 代码：

```go
func main() { 
   c, _ := net.Dial("unix", "/tmp/aSocket.sock") 
   defer c.Close() 

   go readSocket(c) 
   n := 0 
   for { 
         message := []byte("Hi there: " + strconv.Itoa(n) + "\n") 
         _, _ = c.Write(message) 
         time.Sleep(5 * time.Second) 
         n = n + 1 
   } 
} 
```

使用`readUNIX.go`需要另一个进程的存在，该进程也读取和写入同一个套接字文件(`/tmp/aSocket.sock`)。

生成的输出取决于另一部分的实现：在这种情况下，输出如下：

```go
$ go run readUNIX.go
Read: Hi there: 0
Read: Hi there: 1
```

如果找不到套接字文件或没有程序在监听它，您将收到以下错误消息：

```go
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x0 pc=0x10cfe77]

goroutine 1 [running]:
main.main()
      /Users/mtsouk/Desktop/goBook/ch/ch8/code/readUNIX.go:21 +0x67
exit status 2
```

# Go 中的 RPC

RPC 代表**远程过程调用**，是一种执行对远程服务器的函数调用并在客户端获取答案的方式。再次，您将不得不等到第十二章，*网络编程*，以了解如何在 Go 中开发 RPC 服务器和 RPC 客户端。

# 在 Go 中编程 Unix shell

本节将简要而天真地呈现可以用作 Unix shell 开发基础的 Go 代码。除了`exit`命令外，程序能识别的唯一其他命令是`version`命令，它只是打印程序的版本。所有其他用户输入都将在屏幕上回显。

`UNIXshell.go`的 Go 代码将分为三部分呈现。然而，在此之前，我将向您展示 shell 的第一个版本，其中主要包含注释，以更好地理解我通常如何开始实现一个相对具有挑战性的程序：

```go
package main 

import ( 
   "fmt" 
) 

func main() { 

   // Present prompt 

   // Read a line 

   // Get the first word of the line 

   // If it is a built-in shell command, execute the command 

   // otherwise, echo the command 

} 
```

这更多或多少是我作为起点使用的算法：好处是注释简要地展示了程序的操作方式。请记住，算法不依赖于编程语言。之后，开始实现事物会更容易，因为你知道你想要做什么。

因此，shell 最终版本的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "os" 
   "strings" 
) 

var VERSION string = "0.2" 
```

第二部分如下：

```go
func main() { 
   scanner := bufio.NewScanner(os.Stdin) 
   fmt.Print("> ") 
   for scanner.Scan() { 

         line := scanner.Text() 
         words := strings.Split(line, " ") 
         command := words[0] 
```

在这里，您只需逐行从用户那里读取输入并找出输入的第一个单词。

`UNIXshell.go`的最后一部分如下：

```go
         switch command { 
         case "exit": 
               fmt.Println("Exiting...") 
               os.Exit(0) 
         case "version": 
               fmt.Println(VERSION) 
         default: 
               fmt.Println(line) 
         } 

         fmt.Print("> ") 
   } 
} 
```

上述的 Go 代码检查用户给出的命令并相应地采取行动。

执行`UNIXshell.go`并与其交互将生成以下输出：

```go
$ go run UNIXshell.go
> version
0.2
> ls -l
ls -l
> exit
Exiting...
```

如果你想了解如何在 Go 中创建自己的 Unix shell，可以访问[`github.com/elves/elvish`](https://github.com/elves/elvish)。

# 另一个小的 Go 更新

在我写这一章时，Go 已经更新：这是一个小更新，主要是修复了一些错误：

```go
$ date
Thu May 25 06:30:53 EEST 2017
$ go version
go version go1.8.3 darwin/amd64
```

# 练习

1.  将`plotIP.go`的绘图功能放入一个 Go 包中，并使用该包重写`plotIP.go`和`plotData.go`。

1.  查看第六章的`ddGo.go` Go 代码，*文件输入和输出*，以便在接收`SIGINFO`信号时打印有关其进度的信息。

1.  更改`cat.go`的 Go 代码以支持多个输入文件。

1.  更改`plotData.go`的代码，以便在生成的图像上打印网格线。

1.  更改`plotData.go`的代码，以便在图表的条之间留出一点空间。

1.  尝试通过为其添加新功能使`UNIXshell.go`程序变得更好一点。

# 摘要

在本章中，我们讨论了许多有趣和方便的主题，包括信号处理和在 Go 中创建图形图像。此外，我们还教会了您如何在 Go 程序中添加对 Unix 管道的支持。

在下一章中，我们将讨论 Go 最独特的特性，即 goroutines。您将学习什么是 goroutine，如何创建和同步它们，以及如何创建通道和管道。请记住，许多人来学习现代和安全的编程语言，但留下来是因为它的 goroutines！
