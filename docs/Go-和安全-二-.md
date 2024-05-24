# Go 和安全（二）

> 原文：[`zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12`](https://zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：取证

取证是收集证据以侦测犯罪。数字取证简单地指寻找数字证据，包括定位可能包含相关信息的异常文件，搜索隐藏数据，弄清楚文件最后修改时间，弄清楚谁发送了电子邮件，对文件进行散列，收集有关攻击 IP 的信息，或者捕获网络通信。

除了取证，本章还将涵盖隐写术的基本示例——将存档隐藏在图像中。隐写术是一种用来隐藏信息在其他信息中的技巧，使其不容易被发现。

散列，虽然与取证相关，但在《密码学》第六章中有所涵盖，数据包捕获则在第五章中有所涵盖，《数据包捕获和注入》。您将在本书的所有章节中找到对取证调查员有用的示例。

在本章中，您将学习以下主题：

+   文件取证

+   获取基本文件信息

+   查找大文件

+   查找最近更改的文件

+   读取磁盘的引导扇区

+   网络取证

+   查找主机名和 IP 地址

+   查找 MX 邮件记录

+   查找主机的名称服务器

+   隐写术

+   在图像中隐藏存档

+   检测图像中隐藏的存档

+   生成随机图像

+   创建 ZIP 存档

# 文件

文件取证很重要，因为攻击者可能留下痕迹，需要在进行更多更改或丢失任何信息之前收集证据。这包括确定谁拥有文件，它上次更改是什么时候，谁可以访问它，以及查看文件中是否有任何隐藏数据。

# 获取文件信息

让我们从简单的事情开始。这个程序将打印有关文件的信息，即最后修改时间，所有者是谁，它有多少字节，以及它的权限是什么。这也将作为一个很好的测试，以确保您的 Go 开发环境设置正确。

如果调查员发现了异常文件，首先要做的是检查所有基本元数据。这将提供有关文件所有者、哪些组可以访问它、最后修改时间、它是否是可执行文件以及它有多大的信息。所有这些信息都有潜在的用途。

我们将使用的主要函数是`os.Stat()`。这将返回一个`FileInfo`结构，我们将打印出来。我们必须在开始时导入`os`包以调用`os.Stat()`。从`os.Stat()`返回两个变量，这与许多只允许一个返回变量的语言不同。您可以使用下划线(`_`)符号代替变量名来忽略返回变量，例如您想要忽略的错误。

我们导入的`fmt`（格式）包包含典型的打印函数，如`fmt.Println()`和`fmt.Printf()`。`log`包包含`log.Printf()`和`log.Println()`。`fmt`和`log`之间的区别在于`log`在消息之前打印出`时间戳`，并且它是线程安全的。

`log`包有一个`fmt`中没有的函数，那就是`log.Fatal()`，它在打印后立即调用`os.Exit(1)`。`log.Fatal()`函数对处理某些错误条件很有用，通过打印错误并退出。如果您想要干净的输出并具有完全控制，请使用`fmt print`函数。如果每条消息上都有时间戳会很有用，请使用`log`包的打印函数。在收集取证线索时，记录您执行每个操作的时间很重要。

在这个示例中，变量在`main`函数之前的自己的部分中定义。这个范围内的变量对整个包都是可用的。这意味着每个函数都在同一个文件中，其他文件与相同的包声明在同一个目录中。定义变量的这种方法只是为了表明在 Go 中是可能的。这是 Pascal 对语言的影响之一，还有`:=`运算符。在后续示例中，为了节省空间，我们将利用*声明和赋值*运算符或`:=`符号。这在编写代码时很方便，因为你不必先声明变量类型。它会在编译时推断数据类型。然而，在阅读源代码时，显式声明变量类型可以帮助读者浏览代码。我们也可以将整个`var`声明放在`main`函数内部以进一步限制范围：

```go
package main

import (
   "fmt"
   "log"
   "os"
)

var (
   fileInfo os.FileInfo
   err error
)

func main() {
   // Stat returns file info. It will return
   // an error if there is no file.
   fileInfo, err = os.Stat("test.txt")
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println("File name:", fileInfo.Name())
   fmt.Println("Size in bytes:", fileInfo.Size())
   fmt.Println("Permissions:", fileInfo.Mode())
   fmt.Println("Last modified:", fileInfo.ModTime())
   fmt.Println("Is Directory: ", fileInfo.IsDir())
   fmt.Printf("System interface type: %T\n", fileInfo.Sys())
   fmt.Printf("System info: %+v\n\n", fileInfo.Sys())
}
```

# 查找最大的文件

在调查时，大文件总是主要嫌疑对象。大型数据库转储、密码转储、彩虹表、信用卡缓存、窃取的知识产权和其他数据通常存储在一个大型存档中，如果你有合适的工具，很容易发现。此外，找到异常大的图像或视频文件也会很有帮助，因为它们可能包含了隐写信息。隐写术在本章中进一步介绍。

该程序将在一个目录和所有子目录中搜索所有文件并按文件大小进行排序。我们将使用`ioutil.ReadDir()`来探索初始目录，以获取`os.FileInfo`结构的内容切片。要检查文件是否为目录，我们将使用`os.IsDir()`。然后，我们将创建一个名为`FileNode`的自定义数据结构来存储我们需要的信息。我们使用链表来存储文件信息。在将元素插入列表之前，我们将遍历它以找到正确的位置，以便保持列表正确排序。请注意，在类似`/`的目录上运行程序可能需要很长时间。尝试更具体的目录，比如你的`home`文件夹：

```go
package main

import (
   "container/list"
   "fmt"
   "io/ioutil"
   "log"
   "os"
   "path/filepath"
)

type FileNode struct {
   FullPath string
   Info os.FileInfo
}

func insertSorted(fileList *list.List, fileNode FileNode) {
   if fileList.Len() == 0 { 
      // If list is empty, just insert and return
      fileList.PushFront(fileNode)
      return
   }

   for element := fileList.Front(); element != nil; element =    
      element.Next() {
      if fileNode.Info.Size() < element.Value.(FileNode).Info.Size()       
      {
         fileList.InsertBefore(fileNode, element)
         return
      }
   }
   fileList.PushBack(fileNode)
}

func getFilesInDirRecursivelyBySize(fileList *list.List, path string) {
   dirFiles, err := ioutil.ReadDir(path)
   if err != nil {
      log.Println("Error reading directory: " + err.Error())
   }

   for _, dirFile := range dirFiles {
      fullpath := filepath.Join(path, dirFile.Name())
      if dirFile.IsDir() {
         getFilesInDirRecursivelyBySize(
            fileList,
            filepath.Join(path, dirFile.Name()),
         )
      } else if dirFile.Mode().IsRegular() {
         insertSorted(
            fileList,
            FileNode{FullPath: fullpath, Info: dirFile},
         )
      }
   }
}

func main() {
   fileList := list.New()
   getFilesInDirRecursivelyBySize(fileList, "/home")

   for element := fileList.Front(); element != nil; element =   
      element.Next() {
      fmt.Printf("%d ", element.Value.(FileNode).Info.Size())
      fmt.Printf("%s\n", element.Value.(FileNode).FullPath)
   }
}
```

# 查找最近修改过的文件

在对受害者机器进行取证时，你可以做的第一件事之一是查找最近修改过的文件。这可能会给你一些线索，比如攻击者在哪里寻找，他们修改了什么设置，或者他们的动机是什么。

然而，如果调查人员正在查看攻击者的机器，那么目标略有不同。最近访问的文件可能会给出一些线索，比如他们用来攻击的工具，他们可能隐藏数据的地方，或者他们使用的软件。

以下示例将搜索一个目录和子目录，找到所有文件并按最后修改时间进行排序。这个示例非常类似于前一个示例，只是排序是通过使用`time.Time.Before()`函数比较时间戳来完成的：

```go
package main

import (
   "container/list"
   "fmt"
   "io/ioutil"
   "log"
   "os"
   "path/filepath"
)

type FileNode struct {
   FullPath string
   Info os.FileInfo
}

func insertSorted(fileList *list.List, fileNode FileNode) {
   if fileList.Len() == 0 { 
      // If list is empty, just insert and return
      fileList.PushFront(fileNode)
      return
   }

   for element := fileList.Front(); element != nil; element = 
      element.Next() {
      if fileNode.Info.ModTime().Before(element.Value.
        (FileNode).Info.ModTime()) {
            fileList.InsertBefore(fileNode, element)
            return
        }
    }

    fileList.PushBack(fileNode)
}

func GetFilesInDirRecursivelyBySize(fileList *list.List, path string) {
    dirFiles, err := ioutil.ReadDir(path)
    if err != nil {
        log.Println("Error reading directory: " + err.Error())
    }

    for _, dirFile := range dirFiles {
        fullpath := filepath.Join(path, dirFile.Name())
        if dirFile.IsDir() {
            GetFilesInDirRecursivelyBySize(
            fileList,
            filepath.Join(path, dirFile.Name()),
            )
        } else if dirFile.Mode().IsRegular() {
           insertSorted(
              fileList,
              FileNode{FullPath: fullpath, Info: dirFile},
           )
        }
    }
}

func main() {
    fileList := list.New()
    GetFilesInDirRecursivelyBySize(fileList, "/")

    for element := fileList.Front(); element != nil; element =    
       element.Next() {
        fmt.Print(element.Value.(FileNode).Info.ModTime())
        fmt.Printf("%s\n", element.Value.(FileNode).FullPath)
    }
}
```

# 读取引导扇区

该程序将读取磁盘的前 512 个字节，并将结果打印为十进制值、十六进制和字符串。`io.ReadFull()`函数类似于普通读取，但它确保你提供的数据字节片段完全填充。如果文件中的字节数不足以填充字节片段，则返回错误。

这个程序的一个实际用途是检查机器的引导扇区是否已被修改。Rootkits 和恶意软件可能通过修改引导扇区来劫持引导过程。您可以手动检查它是否有任何奇怪的东西，或者与已知的良好版本进行比较。也许可以比较机器的备份映像或新安装，看看是否有任何变化。

请注意，您可以在技术上传递任何文件名，而不是特定的磁盘，因为在 Linux 中，一切都被视为文件。如果直接传递设备的名称，例如`/dev/sda`，它将读取磁盘的前`512`个字节，即引导扇区。主要磁盘设备通常是`/dev/sda`，但也可能是`/dev/sdb`或`/dev/sdc`。使用`mount`或`df`工具获取有关磁盘名称的更多信息。您需要以`sudo`身份运行应用程序，以便具有直接读取磁盘设备的权限。

有关文件、输入和输出的更多信息，请查看`os`、`bufio`和`io`包，如下面的代码块所示：

```go
package main

// Device is typically /dev/sda but may also be /dev/sdb, /dev/sdc
// Use mount, or df -h to get info on which drives are being used
// You will need sudo to access some disks at this level

import (
   "io"
   "log"
   "os"
)

func main() {
   path := "/dev/sda"
   log.Println("[+] Reading boot sector of " + path)

   file, err := os.Open(path)
   if err != nil {
      log.Fatal("Error: " + err.Error())
   }

   // The file.Read() function will read a tiny file in to a large
   // byte slice, but io.ReadFull() will return an
   // error if the file is smaller than the byte slice.
   byteSlice := make([]byte, 512)
   // ReadFull Will error if 512 bytes not available to read
   numBytesRead, err := io.ReadFull(file, byteSlice)
   if err != nil {
      log.Fatal("Error reading 512 bytes from file. " + err.Error())
   }

   log.Printf("Bytes read: %d\n\n", numBytesRead)
   log.Printf("Data as decimal:\n%d\n\n", byteSlice)
   log.Printf("Data as hex:\n%x\n\n", byteSlice)
   log.Printf("Data as string:\n%s\n\n", byteSlice)
}
```

# 隐写术

隐写术是将消息隐藏在非机密消息中的做法。它不应与速记术混淆，速记术是指像法庭记录员一样记录口述的话语的做法。隐写术在历史上已经存在很长时间，一个老式的例子是在服装的缝纫中缝入摩尔斯电码消息。

在数字世界中，人们可以将任何类型的二进制数据隐藏在图像、音频或视频文件中。原始文件的质量可能会受到这一过程的影响。一些图像可以完全保持其原始完整性，但它们在形式上隐藏了额外的数据，如`.zip`或`.rar`存档。一些隐写术算法很复杂，将原始二进制数据隐藏在每个字节的最低位中，只轻微降低原始质量。其他隐写术算法更简单，只是将图像文件和存档合并成一个文件。我们将看看如何将存档隐藏在图像中，以及如何检测隐藏的存档。

# 生成具有随机噪声的图像

该程序将创建一个 JPEG 图像，其中每个像素都设置为随机颜色。这是一个简单的程序，因此我们只有一个可用的 jpeg 图像可供使用。Go 标准库配备了`jpeg`、`gif`和`png`包。所有不同类型的图像的接口都是相同的，因此从`jpeg`切换到`gif`或`png`包非常容易：

```go
package main

import (
   "image"
   "image/jpeg"
   "log"
   "math/rand"
   "os"
)

func main() {
   // 100x200 pixels
   myImage := image.NewRGBA(image.Rect(0, 0, 100, 200))

   for p := 0; p < 100*200; p++ {
      pixelOffset := 4 * p
      myImage.Pix[0+pixelOffset] = uint8(rand.Intn(256)) // Red
      myImage.Pix[1+pixelOffset] = uint8(rand.Intn(256)) // Green
      myImage.Pix[2+pixelOffset] = uint8(rand.Intn(256)) // Blue
      myImage.Pix[3+pixelOffset] = 255 // Alpha
   }

   outputFile, err := os.Create("test.jpg")
   if err != nil {
      log.Fatal(err)
   }

   jpeg.Encode(outputFile, myImage, nil)

   err = outputFile.Close()
   if err != nil {
      log.Fatal(err)
   }
}
```

# 创建 ZIP 存档

该程序将创建一个 ZIP 存档，以便我们在隐写术实验中使用。Go 标准库有一个`zip`包，但它也支持`tar`包的 TAR 存档。此示例生成一个包含两个文件的 ZIP 文件：`test.txt`和`test2.txt`。为了保持简单，每个文件的内容都被硬编码为源代码中的字符串：

```go
package main

import (
   "crypto/md5"
   "crypto/sha1"
   "crypto/sha256"
   "crypto/sha512"
   "fmt"
   "io/ioutil"
   "log"
   "os"
)

func printUsage() {
   fmt.Println("Usage: " + os.Args[0] + " <filepath>")
   fmt.Println("Example: " + os.Args[0] + " document.txt")
}

func checkArgs() string {
   if len(os.Args) < 2 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1]
}

func main() {
   filename := checkArgs()

   // Get bytes from file
   data, err := ioutil.ReadFile(filename)
   if err != nil {
      log.Fatal(err)
   }

   // Hash the file and output results
   fmt.Printf("Md5: %x\n\n", md5.Sum(data))
   fmt.Printf("Sha1: %x\n\n", sha1.Sum(data))
   fmt.Printf("Sha256: %x\n\n", sha256.Sum256(data))
   fmt.Printf("Sha512: %x\n\n", sha512.Sum512(data))
}
```

# 创建隐写图像存档

现在我们有了一张图像和一个 ZIP 存档，我们可以将它们组合在一起，将存档“隐藏”在图像中。这可能是最原始的隐写术形式。更高级的方法是逐字节拆分文件，将信息存储在图像的低位中，使用特殊程序从图像中提取数据，然后重建原始数据。这个例子很好，因为我们可以很容易地测试和验证它是否仍然作为图像加载，并且仍然像 ZIP 存档一样运行。

以下示例将采用 JPEG 图像和 ZIP 存档，并将它们组合在一起创建一个隐藏的存档。文件将保留`.jpg`扩展名，并且仍然可以像正常图像一样运行和查看。但是，该文件仍然可以作为 ZIP 存档工作。您可以解压缩`.jpg`文件，存档文件将被提取出来：

```go
package main

import (
   "io"
   "log"
   "os"
)

func main() {
   // Open original file
   firstFile, err := os.Open("test.jpg")
   if err != nil {
      log.Fatal(err)
   }
   defer firstFile.Close()

   // Second file
   secondFile, err := os.Open("test.zip")
   if err != nil {
      log.Fatal(err)
   }
   defer secondFile.Close()

   // New file for output
   newFile, err := os.Create("stego_image.jpg")
   if err != nil {
      log.Fatal(err)
   }
   defer newFile.Close()

   // Copy the bytes to destination from source
   _, err = io.Copy(newFile, firstFile)
   if err != nil {
      log.Fatal(err)
   }
   _, err = io.Copy(newFile, secondFile)
   if err != nil {
      log.Fatal(err)
   }
}

```

# 在 JPEG 图像中检测 ZIP 存档

如果使用前面示例中的技术隐藏数据，则可以通过在图像中搜索 ZIP 文件签名来检测数据。文件可能具有`.jpg`扩展名，并且在照片查看器中仍然可以正确加载，但它可能仍然在文件中存储有 ZIP 存档。以下程序将搜索文件并查找 ZIP 文件签名。我们可以对前面示例中创建的文件运行它：

```go
package main

import (
   "bufio"
   "bytes"
   "log"
   "os"
)

func main() {
   // Zip signature is "\x50\x4b\x03\x04"
   filename := "stego_image.jpg"
   file, err := os.Open(filename)
   if err != nil {
      log.Fatal(err)
   }
   bufferedReader := bufio.NewReader(file)

   fileStat, _ := file.Stat()
   // 0 is being cast to an int64 to force i to be initialized as
   // int64 because filestat.Size() returns an int64 and must be
   // compared against the same type
   for i := int64(0); i < fileStat.Size(); i++ {
      myByte, err := bufferedReader.ReadByte()
      if err != nil {
         log.Fatal(err)
      }

      if myByte == '\x50' { 
         // First byte match. Check the next 3 bytes
         byteSlice := make([]byte, 3)
         // Get bytes without advancing pointer with Peek
         byteSlice, err = bufferedReader.Peek(3)
         if err != nil {
            log.Fatal(err)
         }

         if bytes.Equal(byteSlice, []byte{'\x4b', '\x03', '\x04'}) {
            log.Printf("Found zip signature at byte %d.", i)
         }
      }
   }
}
```

# 网络

有时，日志中会出现奇怪的 IP 地址，您需要查找更多信息，或者可能有一个您需要根据 IP 地址定位的域名。这些示例演示了收集有关主机的信息。数据包捕获也是网络取证调查的一个重要部分，但是关于数据包捕获还有很多要说，因此第五章，*数据包捕获和注入*专门讨论了数据包捕获和注入。

# 从 IP 地址查找主机名

该程序将接受一个 IP 地址并找出主机名。`net.parseIP()`函数用于验证提供的 IP 地址，`net.LookupAddr()`完成了查找主机名的真正工作。

默认情况下，使用纯 Go 解析器。可以通过设置`GODEBUG`环境变量的`netdns`值来覆盖解析器。将`GODEBUG`的值设置为`go`或`cgo`。您可以在 Linux 中使用以下 shell 命令来执行此操作：

```go
export GODEBUG=netdns=go # force pure Go resolver (Default)
export GODEBUG=netdns=cgo # force cgo resolver
```

以下是程序的代码：

```go
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No IP address argument provided.")
   }
   arg := os.Args[1]

   // Parse the IP for validation
   ip := net.ParseIP(arg)
   if ip == nil {
      log.Fatal("Valid IP not detected. Value provided: " + arg)
   }

   fmt.Println("Looking up hostnames for IP address: " + arg)
   hostnames, err := net.LookupAddr(ip.String())
   if err != nil {
      log.Fatal(err)
   }
   for _, hostnames := range hostnames {
      fmt.Println(hostnames)
   }
}
```

# 从主机名查找 IP 地址

以下示例接受主机名并返回 IP 地址。它与先前的示例非常相似，但是顺序相反。`net.LookupHost()`函数完成了大部分工作：

```go
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No hostname argument provided.")
   }
   arg := os.Args[1]

   fmt.Println("Looking up IP addresses for hostname: " + arg)

   ips, err := net.LookupHost(arg)
   if err != nil {
      log.Fatal(err)
   }
   for _, ip := range ips {
      fmt.Println(ip)
   }
}
```

# 查找 MX 记录

该程序将接受一个域名并返回 MX 记录。MX 记录，或邮件交换记录，是指向邮件服务器的 DNS 记录。例如，[`www.devdungeon.com/`](https://www.devdungeon.com/)的 MX 服务器是`mail.devdungeon.com`。`net.LookupMX()`函数执行此查找并返回`net.MX`结构的切片：

```go
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No domain name argument provided")
   }
   arg := os.Args[1]

   fmt.Println("Looking up MX records for " + arg)

   mxRecords, err := net.LookupMX(arg)
   if err != nil {
      log.Fatal(err)
   }
   for _, mxRecord := range mxRecords {
      fmt.Printf("Host: %s\tPreference: %d\n", mxRecord.Host,   
         mxRecord.Pref)
   }
}
```

# 查找主机名的域名服务器

该程序将查找与给定主机名关联的域名服务器。这里的主要功能是`net.LookupNS()`：

```go
package main

import (
   "fmt"
   "log"
   "net"
   "os"
)

func main() {
   if len(os.Args) != 2 {
      log.Fatal("No domain name argument provided")
   }
   arg := os.Args[1]

   fmt.Println("Looking up nameservers for " + arg)

   nameservers, err := net.LookupNS(arg)
   if err != nil {
      log.Fatal(err)
   }
   for _, nameserver := range nameservers {
      fmt.Println(nameserver.Host)
   }
}
```

# 总结

阅读完本章后，您现在应该对数字取证调查的目标有基本的了解。关于这些主题中的每一个都可以说更多，取证是一门需要自己的书籍，更不用说一章了。

将您已阅读的示例作为起点，思考一下如果您收到了一台被入侵的机器，您将寻找什么样的信息，以及您的目标是弄清楚攻击者是如何进入的，发生的时间，他们访问了什么，他们修改了什么，他们的动机是什么，有多少数据被外泄，以及您可以找到的任何其他信息，以确定行动者是谁或在系统上采取了什么行动。

熟练的对手将尽一切努力掩盖自己的踪迹，避免取证检测。因此，重要的是要及时了解正在使用的最新工具和趋势，以便在调查时知道要寻找的技巧和线索。

这些示例可以进行扩展，自动化，并集成到执行更大规模的取证搜索的其他应用程序中。借助 Go 的可扩展性，可以轻松地创建工具，以有效的方式搜索整个文件系统或网络。

在下一章中，我们将学习使用 Go 进行数据包捕获。我们将从基础知识开始，例如获取网络设备列表和将网络流量转储到文件中。然后，我们将讨论使用过滤器查找特定的网络流量。此外，我们将探讨使用 Go 接口解码和检查数据包的更高级技术。我们还将涵盖创建自定义数据包层以及从网络卡发送数据包的技术，从而允许您发送任意数据包。


# 第五章：数据包捕获和注入

数据包捕获是监视通过网络传输的原始流量的过程。这适用于有线以太网和无线网络设备。在数据包捕获方面，`tcpdump`和`libpcap`包是标准。它们是在 20 世纪 80 年代编写的，至今仍在使用。`gopacket`包不仅包装了 C 库，还添加了 Go 抽象层，使其更符合 Go 的习惯用法并且更实用。

`pcap`库允许您收集有关网络设备的信息，从网络中读取数据包，将流量存储在`.pcap`文件中，根据多种条件过滤流量，或伪造自定义数据包并通过网络设备发送它们。对于`pcap`库，过滤是使用**伯克利数据包过滤器**（**BPF**）完成的。

数据包捕获有无数种用途。它可以用于设置蜜罐并监视接收到的流量类型。它可以帮助进行取证调查，以确定哪些主机表现恶意，哪些主机被利用。它可以帮助识别网络中的瓶颈。它也可以被恶意使用来从无线网络中窃取信息，执行数据包扫描，模糊测试，ARP 欺骗和其他类型的攻击。

这些示例需要一个非 Go 依赖项和一个`libpcap`包，因此在运行时可能会更具挑战性。如果您尚未将 Linux 作为主要桌面系统使用，我强烈建议您在虚拟机中使用 Ubuntu 或其他 Linux 发行版以获得最佳结果。

Tcpdump 是由`libpcap`的作者编写的应用程序。Tcpdump 提供了一个用于捕获数据包的命令行实用程序。这些示例将允许您复制`tcpdump`包的功能，并将其嵌入到其他应用程序中。其中一些示例与`tcpdump`的现有功能非常相似，如果适用，将提供`tcpdump`的示例用法。由于`gopacket`和`tcpdump`都依赖于相同的底层`libpcap`包，因此它们之间的文件格式是兼容的。您可以使用`tcpdump`捕获文件，并使用`gopacket`读取它们，也可以使用`gopacket`捕获数据包，并使用任何使用`libpcap`的应用程序读取它们，例如 Wireshark。

`gopacket`包的官方文档可在[`godoc.org/github.com/google/gopacket`](https://godoc.org/github.com/google/gopacket)找到。

# 先决条件

在运行这些示例之前，您需要安装`libpcap`。此外，我们还必须使用第三方 Go 包。幸运的是，这个包是由 Google 提供的，是一个可信赖的来源。Go 的`get`功能将下载并安装远程包。Git 也将需要用于使`go get`正常工作。

# 安装 libpcap 和 Git

`libpcap`包依赖项在大多数系统上都没有预安装，并且安装过程对每个操作系统都是不同的。在这里，我们将介绍 Ubuntu、Windows 和 macOS 上安装`libpcap`和`git`的步骤。我强烈建议您使用 Ubuntu 或其他 Linux 发行版以获得最佳结果。没有`libpcap`，`gopacket`将无法正常工作，而`git`是获取`gopacket`依赖项所必需的。

# 在 Ubuntu 上安装 libpcap

在 Ubuntu 中，默认情况下已经安装了`libpcap-0.8`。但是，要安装`gopacket`库，你还需要开发包中的头文件。你可以通过`libpcap-dev`包安装头文件。我们还将安装`git`，因为在安装`gopacket`时稍后需要运行`go get`命令。

```go
sudo apt-get install git libpcap-dev
```

# 在 Windows 上安装 libpcap

Windows 是最棘手的，也是出现最多问题的地方。Windows 实现的支持并不是很好，你的使用体验可能会有所不同。WinPcap 与 libpcap 兼容，这些示例中使用的源代码也可以直接在 Windows 上运行而无需修改。在 Windows 上运行时唯一显著的区别是网络设备的命名。

WinPcap 安装程序可从[`www.winpcap.org/`](https://www.winpcap.org/)获取，并且是一个必需的组件。如果需要开发人员包，可以在[`www.winpcap.org/devel.htm`](https://www.winpcap.org/devel.htm)获取，其中包含用 C 编写的包含文件和示例程序。对于大多数情况，您不需要开发人员包。Git 可以从[`git-scm.com/download/win`](https://git-scm.com/download/win)获取。您还需要 MinGW 作为编译器，可以从[`www.mingw.org`](http://www.mingw.org)获取。您需要确保 32 位和 64 位设置匹配。您可以设置`GOARCH=386`或`GOARCH=amd64`环境变量来在 32 位和 64 位之间切换。

# 在 macOS 上安装 libpcap

在 macOS 中，`libpcap`已经安装。您还需要 Git，可以通过 Homebrew 在[`brew.sh`](https://brew.sh)获取，或者通过 Git 软件包安装程序在[`git-scm.com/downloads`](https://git-scm.com/downloads)获取。

# 安装 gopacket

在满足`libpcap`和`git`软件包的要求后，您可以从 GitHub 获取`gopacket`软件包：

```go
go get github.com/google/gopacket  
```

# 权限问题

在 Linux 和 Mac 环境中执行程序时，可能会遇到访问网络设备时的权限问题。使用`sudo`来提升权限或切换用户到`root`来运行示例，但这并不推荐。

# 获取网络设备列表

`pcap`库的一部分包括一个用于获取网络设备列表的函数。

此程序将简单地获取网络设备列表并列出它们的信息。在 Linux 中，常见的默认设备名称是`eth0`或`wlan0`。在 Mac 上，是`en0`。在 Windows 上，名称不可读，因为它们更长并代表唯一的 ID。您可以使用设备名称作为字符串来标识以后示例中要捕获的设备。如果您没有看到确切设备的列表，可能需要以管理员权限运行示例（例如`sudo`）。

列出设备的等效`tcpdump`命令如下：

```go
tcpdump -D
```

或者，您可以使用以下命令：

```go
tcpdump --list-interfaces
```

您还可以使用`ifconfig`和`ip`等实用程序来获取您的网络设备的名称：

```go
package main

import (
   "fmt"
   "log"
   "github.com/google/gopacket/pcap"
)

func main() {
   // Find all devices
   devices, err := pcap.FindAllDevs()
   if err != nil {
      log.Fatal(err)
   }

   // Print device information
   fmt.Println("Devices found:")
   for _, device := range devices {
      fmt.Println("\nName: ", device.Name)
      fmt.Println("Description: ", device.Description)
      fmt.Println("Devices addresses: ", device.Description)
      for _, address := range device.Addresses {
         fmt.Println("- IP address: ", address.IP)
         fmt.Println("- Subnet mask: ", address.Netmask)
      }
   }
}
```

# 捕获数据包

以下程序演示了捕获数据包的基础知识。设备名称以字符串形式传递。如果您不知道设备名称，可以使用前面的示例来获取机器上可用设备的列表。如果您没有看到确切的设备名称列表，可能需要提升权限并使用`sudo`来运行程序。

混杂模式是一种选项，您可以启用它来监听并捕获并非发送给您设备的数据包。混杂模式在无线设备中尤其相关，因为无线网络设备实际上有能力捕获空中本来是发给其他接收者的数据包。

无线流量特别容易受到*嗅探*的影响，因为所有数据包都是通过空气广播而不是通过以太网传输，以太网需要物理访问才能拦截流量。提供没有加密的免费无线互联网在咖啡店和其他场所非常常见。这对客人来说很方便，但会使你的信息处于风险之中。如果场所提供加密的无线互联网，并不代表它自动更安全。如果密码被张贴在墙上，或者自由分发，那么任何有密码的人都可以解密无线流量。增加对客人无线网络的安全性的一种流行技术是使用捕获门户。捕获门户要求用户以某种方式进行身份验证，即使是作为访客，然后他们的会话被分割并使用单独的加密，这样其他人就无法解密它。

提供完全未加密流量的无线接入点必须小心使用。如果你连接到一个传递敏感信息的网站，请确保它使用 HTTPS，这样你和你访问的网站之间的数据就会被加密。VPN 连接也可以在未加密的通道上提供加密隧道。

一些网站是由不知情或疏忽的程序员构建的，他们在服务器上没有实现 SSL。一些网站只加密登录页面，以确保你的密码安全，但随后以明文传递会话 cookie。这意味着任何可以拦截无线流量的人都可以看到会话 cookie 并使用它来冒充受害者访问网站。网站将把攻击者视为受害者已登录。攻击者永远不会得知密码，但只要会话保持活动状态，他们就不需要密码。

一些网站的会话没有过期日期，它们会一直保持活动状态，直到明确退出登录。移动应用程序特别容易受到这种影响，因为用户很少退出并重新登录移动应用程序。关闭一个应用程序并重新打开它并不一定会创建一个新的会话。

这个例子将打开网络设备进行实时捕获，然后打印每个接收到的数据包的详细信息。程序将继续运行，直到使用*Ctrl* + *C* 杀死程序。

```go
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "log"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous,  
      timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // Use the handle as a packet source to process all packets
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      // Process packet here
      fmt.Println(packet)
   }
}
```

# 使用过滤器捕获

以下程序演示了如何设置过滤器。过滤器使用 BPF 格式。如果你曾经使用过 Wireshark，你可能已经熟悉过滤器了。有许多可以逻辑组合的过滤选项。过滤器可以非常复杂，在网上有许多常见过滤器和巧妙技巧的速查表。以下是一些基本过滤器的示例，以便让你了解一些基本过滤器的想法：

+   `host 192.168.0.123`

+   `dst net 192.168.0.0/24`

+   `port 22`

+   `not broadcast and not multicast`

前面的一些过滤器应该是不言自明的。`host`过滤器将只显示发送到或从该主机的数据包。`dst net`过滤器将捕获发送到`192.168.0.*`地址的流量。`port`过滤器只监视端口`22`的流量。`not broadcast and not multicast`过滤器演示了如何否定和组合多个过滤器。过滤掉`广播`和`多播`是有用的，因为它们往往会使捕获变得混乱。

一个基本捕获的等效`tcpdump`命令只需运行它并传递一个接口：

```go
tcpdump -i eth0
```

如果你想传递过滤器，只需将它们作为命令行参数传递，就像这样：

```go
tcpdump -i eth0 tcp port 80
```

这个例子使用了一个只捕获 TCP 端口`80`流量的过滤器，这应该是 HTTP 流量。它没有指定本地端口或远程端口是否为`80`，因此它将捕获任何进出的端口`80`流量。如果你在个人电脑上运行它，你可能没有运行 web 服务器，所以它将捕获你通过 web 浏览器进行的 HTTP 流量。如果你在 web 服务器上运行捕获，它将捕获传入的 HTTP 请求流量。

在这个例子中，使用`pcap.OpenLive()`创建了一个网络设备的句柄。在从设备读取数据包之前，使用`handle.SetBPFFilter()`设置了过滤器，然后从句柄中读取数据包。在[`en.wikipedia.org/wiki/Berkeley_Packet_Filter`](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter)上了解更多关于过滤器的信息。

这个例子打开一个网络设备进行实时捕获，然后使用`SetBPFFilter()`设置一个过滤器。在这种情况下，我们将使用`tcp and port 80`过滤器来查找 HTTP 流量。捕获到的任何数据包都会被打印到标准输出：

```go
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "log"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous,  
      timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // Set filter
   var filter string = "tcp and port 80" // or os.Args[1]
   err = handle.SetBPFFilter(filter)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println("Only capturing TCP port 80 packets.")

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      // Do something with a packet here.
      fmt.Println(packet)
   }
}
```

# 将数据保存到 pcap 文件

该程序将执行数据包捕获并将结果存储在文件中。在这个例子中的重要步骤是调用`pcapgo`包——`Writer`的`WriteFileHeader()`函数。之后，`WritePacket()`函数可以用来将所需的数据包写入文件。您可以捕获所有流量，并根据自己的过滤条件选择只写入特定的数据包，如果需要的话。也许您只想将奇数或格式错误的数据包写入日志以记录异常。

要使用`tcpdump`进行等效操作，只需使用`-w`标志和文件名，如下命令所示：

```go
tcpdump -i eth0 -w my_capture.pcap
```

使用这个例子创建的 pcap 文件可以使用 Wireshark 打开，并且可以像使用`tcpdump`创建的文件一样查看。

这个例子创建了一个名为`test.pcap`的输出文件，并打开一个网络设备进行实时捕获。它将 100 个数据包捕获到文件中，然后退出：

```go
package main

import (
   "fmt"
   "os"
   "time"

   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "github.com/google/gopacket/pcapgo"
)

var (
   deviceName        = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = -1 * time.Second
   handle      *pcap.Handle
   packetCount = 0
)

func main() {
   // Open output pcap file and write header
   f, _ := os.Create("test.pcap")
   w := pcapgo.NewWriter(f)
   w.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
   defer f.Close()

   // Open the device for capturing
   handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, 
      timeout)
   if err != nil {
      fmt.Printf("Error opening device %s: %v", deviceName, err)
      os.Exit(1)
   }
   defer handle.Close()

   // Start processing packets
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      // Process packet here
      fmt.Println(packet)
      w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
      packetCount++

      // Only capture 100 and then stop
      if packetCount > 100 {
         break
      }
   }
}
```

# 从 pcap 文件中读取

您可以打开一个 pcap 文件进行离线检查，而不是打开一个设备进行实时捕获。无论是从`pcap.OpenLive()`还是`pcap.OpenOffline()`获取了一个句柄之后，该句柄都会被同等对待。一旦创建了句柄，实时设备和捕获文件之间就没有区别，只是实时设备将继续传递数据包，而文件最终会结束。

您可以使用任何`libpcap`客户端捕获的 pcap 文件，包括 Wireshark、`tcpdump`或其他`gopacket`应用程序。这个例子使用`pcap.OpenOffline()`打开一个名为`test.pcap`的文件，然后使用`range`迭代数据包并打印基本数据包信息。将文件名从`test.pcap`更改为您想要读取的任何文件：

```go
package main

// Use tcpdump to create a test file
// tcpdump -w test.pcap
// or use the example above for writing pcap files

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/pcap"
   "log"
)

var (
   pcapFile = "test.pcap"
   handle   *pcap.Handle
   err      error
)

func main() {
   // Open file instead of device
   handle, err = pcap.OpenOffline(pcapFile)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   // Loop through packets in file
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      fmt.Println(packet)
   }
}
```

# 解码数据包层

数据包可以使用`packet.Layer()`函数逐层解码。该程序将检查数据包，查找 TCP 流量，然后输出以太网层、IP 层、TCP 层和应用层信息。当需要检查流量并根据信息做出决定时，这是非常有用的。当它到达应用层时，它会查找`HTTP`关键字，如果检测到，则打印一条消息：

```go
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "log"
   "strings"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, 
      timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      printPacketInfo(packet)
   }
}

func printPacketInfo(packet gopacket.Packet) {
   // Let's see if the packet is an ethernet packet
   ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
   if ethernetLayer != nil {
      fmt.Println("Ethernet layer detected.")
      ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
      fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
      fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
      // Ethernet type is typically IPv4 but could be ARP or other
      fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
      fmt.Println()
   }

   // Let's see if the packet is IP (even though the ether type told 
   //us)
   ipLayer := packet.Layer(layers.LayerTypeIPv4)
   if ipLayer != nil {
      fmt.Println("IPv4 layer detected.")
      ip, _ := ipLayer.(*layers.IPv4)

      // IP layer variables:
      // Version (Either 4 or 6)
      // IHL (IP Header Length in 32-bit words)
      // TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
      // Checksum, SrcIP, DstIP
      fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
      fmt.Println("Protocol: ", ip.Protocol)
      fmt.Println()
   }

   // Let's see if the packet is TCP
   tcpLayer := packet.Layer(layers.LayerTypeTCP)
   if tcpLayer != nil {
      fmt.Println("TCP layer detected.")
      tcp, _ := tcpLayer.(*layers.TCP)

      // TCP layer variables:
      // SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, 
      //Urgent
      // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
      fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
      fmt.Println("Sequence number: ", tcp.Seq)
      fmt.Println()
   }

   // Iterate over all layers, printing out each layer type
   fmt.Println("All packet layers:")
   for _, layer := range packet.Layers() {
      fmt.Println("- ", layer.LayerType())
   }

   // When iterating through packet.Layers() above,
   // if it lists Payload layer then that is the same as
   // this applicationLayer. applicationLayer contains the payload
   applicationLayer := packet.ApplicationLayer()
   if applicationLayer != nil {
      fmt.Println("Application layer/Payload found.")
      fmt.Printf("%s\n", applicationLayer.Payload())

      // Search for a string inside the payload
      if strings.Contains(string(applicationLayer.Payload()), "HTTP")    
      {
         fmt.Println("HTTP found!")
      }
   }

   // Check for errors
   if err := packet.ErrorLayer(); err != nil {
      fmt.Println("Error decoding some part of the packet:", err)
   }
}
```

# 创建自定义层

您不仅限于最常见的层，比如以太网、IP 和 TCP。您可以创建自己的层。对于大多数人来说，这种用途有限，但在一些极端罕见的情况下，用自定义层替换 TCP 层以满足特定要求可能是有意义的。

这个例子演示了如何创建一个自定义层。这对于实现`gopacket/layers`包中尚未包含的协议非常有用。`gopacket`中已经包含了 100 多种层类型。您可以在任何级别创建自定义层。

这段代码的第一件事是定义一个自定义数据结构来表示我们的层。数据结构不仅保存我们的自定义数据（`SomeByte`和`AnotherByte`），还需要一个字节片来存储实际负载的其余部分，以及其他层（`restOfData`）：

```go
package main

import (
   "fmt"
   "github.com/google/gopacket"
)

// Create custom layer structure
type CustomLayer struct {
   // This layer just has two bytes at the front
   SomeByte    byte
   AnotherByte byte
   restOfData  []byte
}

// Register the layer type so we can use it
// The first argument is an ID. Use negative
// or 2000+ for custom layers. It must be unique
var CustomLayerType = gopacket.RegisterLayerType(
   2001,
   gopacket.LayerTypeMetadata{
      "CustomLayerType",
      gopacket.DecodeFunc(decodeCustomLayer),
   },
)

// When we inquire about the type, what type of layer should
// we say it is? We want it to return our custom layer type
func (l CustomLayer) LayerType() gopacket.LayerType {
   return CustomLayerType
}

// LayerContents returns the information that our layer
// provides. In this case it is a header layer so
// we return the header information
func (l CustomLayer) LayerContents() []byte {
   return []byte{l.SomeByte, l.AnotherByte}
}

// LayerPayload returns the subsequent layer built
// on top of our layer or raw payload
func (l CustomLayer) LayerPayload() []byte {
   return l.restOfData
}

// Custom decode function. We can name it whatever we want
// but it should have the same arguments and return value
// When the layer is registered we tell it to use this decode function
func decodeCustomLayer(data []byte, p gopacket.PacketBuilder) error {
   // AddLayer appends to the list of layers that the packet has
   p.AddLayer(&CustomLayer{data[0], data[1], data[2:]})

   // The return value tells the packet what layer to expect
   // with the rest of the data. It could be another header layer,
   // nothing, or a payload layer.

   // nil means this is the last layer. No more decoding
   // return nil
   // Returning another layer type tells it to decode
   // the next layer with that layer's decoder function
   // return p.NextDecoder(layers.LayerTypeEthernet)

   // Returning payload type means the rest of the data
   // is raw payload. It will set the application layer
   // contents with the payload
   return p.NextDecoder(gopacket.LayerTypePayload)
}

func main() {
   // If you create your own encoding and decoding you can essentially
   // create your own protocol or implement a protocol that is not
   // already defined in the layers package. In our example we are    
   // just wrapping a normal ethernet packet with our own layer.
   // Creating your own protocol is good if you want to create
   // some obfuscated binary data type that was difficult for others
   // to decode. Finally, decode your packets:
   rawBytes := []byte{0xF0, 0x0F, 65, 65, 66, 67, 68}
   packet := gopacket.NewPacket(
      rawBytes,
      CustomLayerType,
      gopacket.Default,
   )
   fmt.Println("Created packet out of raw bytes.")
   fmt.Println(packet)

   // Decode the packet as our custom layer
   customLayer := packet.Layer(CustomLayerType)
   if customLayer != nil {
      fmt.Println("Packet was successfully decoded.")
      customLayerContent, _ := customLayer.(*CustomLayer)
      // Now we can access the elements of the custom struct
      fmt.Println("Payload: ", customLayerContent.LayerPayload())
      fmt.Println("SomeByte element:", customLayerContent.SomeByte)
      fmt.Println("AnotherByte element:",  
         customLayerContent.AnotherByte)
   }
}
```

# 将字节转换为数据包和从数据包转换

在某些情况下，可能有原始字节，您希望将其转换为数据包，或者反之亦然。这个例子创建了一个简单的数据包，然后获取组成数据包的原始字节。然后取这些原始字节并将其转换回数据包以演示这个过程。

在这个例子中，我们将使用`gopacket.SerializeLayers()`创建和序列化一个数据包。数据包由几个层组成：以太网、IP、TCP 和有效负载。在序列化过程中，如果任何数据包返回为 nil，这意味着它无法解码成正确的层（格式错误或不正确的数据包类型）。将数据包序列化到缓冲区后，我们将得到组成数据包的原始字节的副本，使用`buffer.Bytes()`。有了原始字节，我们可以使用`gopacket.NewPacket()`逐层解码数据。通过利用`SerializeLayers()`，您可以将数据包结构转换为原始字节，并使用`gopacket.NewPacket()`，您可以将原始字节转换回结构化数据。

`NewPacket()`将原始字节作为第一个参数。第二个参数是您想要解码的最底层层。它将解码该层以及其上的所有层。`NewPacket()`的第三个参数是解码类型，必须是以下之一：

+   `gopacket.Default`：这是一次性解码所有内容，也是最安全的。

+   `gopacket.Lazy`：这是按需解码，但不是并发安全的。

+   `gopacket.NoCopy`：这不会创建缓冲区的副本。只有在您可以保证内存中的数据包数据不会更改时才使用它

以下是将数据包结构转换为字节，然后再转换回数据包的完整代码：

```go
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
)

func main() {
   payload := []byte{2, 4, 6}
   options := gopacket.SerializeOptions{}
   buffer := gopacket.NewSerializeBuffer()
   gopacket.SerializeLayers(buffer, options,
      &layers.Ethernet{},
      &layers.IPv4{},
      &layers.TCP{},
      gopacket.Payload(payload),
   )
   rawBytes := buffer.Bytes()

   // Decode an ethernet packet
   ethPacket :=
      gopacket.NewPacket(
         rawBytes,
         layers.LayerTypeEthernet,
         gopacket.Default,
      )

   // with Lazy decoding it will only decode what it needs when it 
   //needs it
   // This is not concurrency safe. If using concurrency, use default
   ipPacket :=
      gopacket.NewPacket(
         rawBytes,
         layers.LayerTypeIPv4,
         gopacket.Lazy,
      )

   // With the NoCopy option, the underlying slices are referenced
   // directly and not copied. If the underlying bytes change so will
   // the packet
   tcpPacket :=
      gopacket.NewPacket(
         rawBytes,
         layers.LayerTypeTCP,
         gopacket.NoCopy,
      )

   fmt.Println(ethPacket)
   fmt.Println(ipPacket)
   fmt.Println(tcpPacket)
}
```

# 创建和发送数据包

这个例子做了几件事。首先，它将向您展示如何使用网络设备发送原始字节，这样您就可以几乎像串行连接一样使用它来发送数据。这对于真正的低级数据传输很有用，但如果您想与应用程序交互，您可能希望构建一个其他硬件和软件可以识别的数据包。

它接下来要做的事情是向您展示如何创建一个包含以太网、IP 和 TCP 层的数据包。不过，所有内容都是默认和空的，所以实际上并没有做任何事情。

最后，我们将创建另一个数据包，但实际上会为以太网层填写一些 MAC 地址，为 IPv4 填写一些 IP 地址，为 TCP 层填写一些端口号。您应该看到如何伪造数据包并冒充设备。

TCP 层结构具有`SYN`、`FIN`和`ACK`标志的布尔字段，可以读取或设置。这对于操纵和模糊化 TCP 握手、会话和端口扫描非常有用。

`pcap`库提供了一种发送字节的简单方法，但`gopacket`中的`layers`包协助我们创建了几个层的字节结构。

以下是此示例的代码实现：

```go
package main

import (
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "log"
   "net"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
   buffer      gopacket.SerializeBuffer
   options     gopacket.SerializeOptions
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, 
      timeout)
   if err != nil {
      log.Fatal("Error opening device. ", err)
   }
   defer handle.Close()

   // Send raw bytes over wire
   rawBytes := []byte{10, 20, 30}
   err = handle.WritePacketData(rawBytes)
   if err != nil {
      log.Fatal("Error writing bytes to network device. ", err)
   }

   // Create a properly formed packet, just with
   // empty details. Should fill out MAC addresses,
   // IP addresses, etc.
   buffer = gopacket.NewSerializeBuffer()
   gopacket.SerializeLayers(buffer, options,
      &layers.Ethernet{},
      &layers.IPv4{},
      &layers.TCP{},
      gopacket.Payload(rawBytes),
   )
   outgoingPacket := buffer.Bytes()
   // Send our packet
   err = handle.WritePacketData(outgoingPacket)
   if err != nil {
      log.Fatal("Error sending packet to network device. ", err)
   }

   // This time lets fill out some information
   ipLayer := &layers.IPv4{
      SrcIP: net.IP{127, 0, 0, 1},
      DstIP: net.IP{8, 8, 8, 8},
   }
   ethernetLayer := &layers.Ethernet{
      SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
      DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
   }
   tcpLayer := &layers.TCP{
      SrcPort: layers.TCPPort(4321),
      DstPort: layers.TCPPort(80),
   }
   // And create the packet with the layers
   buffer = gopacket.NewSerializeBuffer()
   gopacket.SerializeLayers(buffer, options,
      ethernetLayer,
      ipLayer,
      tcpLayer,
      gopacket.Payload(rawBytes),
   )
   outgoingPacket = buffer.Bytes()
}
```

# 更快地解码数据包

如果我们知道要期望的层，我们可以使用现有的结构来存储数据包信息，而不是为每个数据包创建新的结构，这需要时间和内存。使用`DecodingLayerParser`更快。这就像编组和解组数据。

这个例子演示了如何在程序开始时创建层变量，并重复使用相同的变量，而不是为每个数据包创建新的变量。使用`gopacket.NewDecodingLayerParser()`创建一个解析器，我们提供了要使用的层变量。这里的一个注意事项是，它只会解码最初创建的层类型。

以下是此示例的代码实现：

```go
package main

import (
   "fmt"
   "github.com/google/gopacket"
   "github.com/google/gopacket/layers"
   "github.com/google/gopacket/pcap"
   "log"
   "time"
)

var (
   device            = "eth0"
   snapshotLen int32 = 1024
   promiscuous       = false
   err         error
   timeout     = 30 * time.Second
   handle      *pcap.Handle
   // Reuse these for each packet
   ethLayer layers.Ethernet
   ipLayer  layers.IPv4
   tcpLayer layers.TCP
)

func main() {
   // Open device
   handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, 
   timeout)
   if err != nil {
      log.Fatal(err)
   }
   defer handle.Close()

   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
      parser := gopacket.NewDecodingLayerParser(
         layers.LayerTypeEthernet,
         &ethLayer,
         &ipLayer,
         &tcpLayer,
      )
      foundLayerTypes := []gopacket.LayerType{}

      err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
      if err != nil {
         fmt.Println("Trouble decoding layers: ", err)
      }

      for _, layerType := range foundLayerTypes {
         if layerType == layers.LayerTypeIPv4 {
            fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
         }
         if layerType == layers.LayerTypeTCP {
            fmt.Println("TCP Port: ", tcpLayer.SrcPort,               
               "->", tcpLayer.DstPort)
            fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", 
               tcpLayer.ACK)
         }
      }
   }
}
```

# 总结

阅读完本章后，您现在应该对`gopacket`包有很好的理解。您应该能够使用本章的示例编写一个简单的数据包捕获应用程序。再次强调，重要的不是记住所有的函数或层的细节。重要的是以高层次理解整体情况，并能够回忆起在范围和实施应用程序时可用的工具。

尝试根据这些示例编写自己的程序，以捕获来自您的计算机的有趣的网络流量。尝试捕获和检查特定端口或应用程序，以查看它在网络上传输时的工作方式。查看使用加密和以明文传输数据的应用程序之间的区别。您可能只是想捕获后台正在进行的所有流量，并查看在您空闲时哪些应用程序在网络上忙碌。

使用`gopacket`库可以构建各种有用的工具。除了基本的数据包捕获以供以后审查之外，您还可以实现一个监控系统，当识别到大量流量激增或发现异常流量时发出警报。

由于`gopacket`库也可以用于发送数据包，因此可以创建高度定制的端口扫描器。您可以制作原始数据包来执行仅进行 TCP SYN 扫描的操作，其中连接从未完全建立；XMAS 扫描，其中所有标志都被打开；NULL 扫描，其中每个字段都设置为 null；以及一系列其他需要对发送的数据包进行完全控制的扫描，包括故意发送格式错误的数据包。您还可以构建模糊测试器，向网络服务发送错误的数据包，以查看其行为。因此，看看您能想出什么样的想法。

在下一章中，我们将学习使用 Go 进行加密。我们将首先看一下哈希、校验和以及安全存储密码。然后我们将研究对称和非对称加密，它们是什么，它们的区别，为什么它们有用，以及如何在 Go 中使用它们。我们将学习如何创建带有证书的加密服务器，以及如何使用加密客户端进行连接。理解加密的应用对于现代安全至关重要，因此我们将研究最常见和实际的用例。


# 第六章：密码学

加密是一种在第三方可以查看通信时保护通信的实践。有双向对称和非对称加密方法，以及单向哈希算法。

加密是现代互联网的关键部分。有了[LetsEncrypt.com](http://www.LetsEncrypt.com)等服务，每个人都可以获得受信任的 SSL 证书。我们的整个基础设施都依赖于加密来保护所有机密数据。正确加密和正确哈希数据非常重要，而且很容易配置错误的服务，使其容易受到攻击或暴露。

本章涵盖以下示例和用例：

+   对称和非对称加密

+   签名和验证消息

+   哈希处理

+   安全存储密码

+   生成安全的随机数

+   创建和使用 TLS/SSL 证书

# 哈希处理

哈希是将可变长度消息转换为唯一的固定长度的字母数字字符串。有各种可用的哈希算法，如 MD5 和 SHA1。哈希是单向且不可逆的，不像对称加密函数（如 AES），如果您有密钥，可以恢复原始消息。由于哈希无法被反转，大多数哈希都会被暴力破解。破解者将构建功耗巨大的装置，配备多个 GPU，以对每个可能的字符组合进行哈希，直到找到与之匹配的哈希。他们还会生成彩虹表或包含所有已生成哈希输出的文件，以进行快速查找。

因此，对哈希进行加盐很重要。加盐是向用户提供的密码末尾添加随机字符串的过程，以增加更多的随机性或熵。考虑一个存储用户登录信息和哈希密码以进行身份验证的应用程序。如果两个用户使用相同的密码，则它们的哈希输出将相同。没有盐，破解者可能会找到多个使用相同密码的人，并且只需要破解一次哈希。通过为每个用户的密码添加唯一的盐，您确保每个用户都具有唯一的哈希值。加盐减少了彩虹表的有效性，因为即使他们知道与每个哈希相关的盐，他们也必须为每个盐生成一个彩虹表，这是耗时的。

哈希通常用于验证密码。另一个常见用途是用于文件完整性。大型下载通常附带文件的 MD5 或 SHA1 哈希。下载后，您可以对文件进行哈希处理，以确保其与预期值匹配。如果不匹配，则下载文件已被修改。哈希还用作记录妥协指标或 IOC 的一种方式。已知恶意或危险的文件会被哈希处理，并且该哈希将存储在目录中。这些通常是公开共享的，以便人们可以检查可疑文件是否存在已知风险。与整个文件相比，存储和比较哈希要高效得多。

# 对小文件进行哈希处理

如果文件小到可以包含在内存中，`ReadFile()`方法可以快速工作。它将整个文件加载到内存中，然后对数据进行摘要。将使用多种不同的哈希算法进行计算：

```go
package main

import (
   "crypto/md5"
   "crypto/sha1"
   "crypto/sha256"
   "crypto/sha512"
   "fmt"
   "io/ioutil"
   "log"
   "os"
)

func printUsage() {
   fmt.Println("Usage: " + os.Args[0] + " <filepath>")
   fmt.Println("Example: " + os.Args[0] + " document.txt")
}

func checkArgs() string {
   if len(os.Args) < 2 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1]
}

func main() {
   filename := checkArgs()

   // Get bytes from file
   data, err := ioutil.ReadFile(filename)
   if err != nil {
      log.Fatal(err)
   }

   // Hash the file and output results
   fmt.Printf("Md5: %x\n\n", md5.Sum(data))
   fmt.Printf("Sha1: %x\n\n", sha1.Sum(data))
   fmt.Printf("Sha256: %x\n\n", sha256.Sum256(data))
   fmt.Printf("Sha512: %x\n\n", sha512.Sum512(data))
}
```

# 对大文件进行哈希处理

在前面的哈希示例中，要进行哈希处理的整个文件在哈希之前被加载到内存中。当文件达到一定大小时，这是不切实际甚至不可能的。物理内存限制将起作用。因为哈希是作为块密码实现的，它将一次操作一个块，而无需一次性将整个文件加载到内存中：

```go
package main

import (
   "crypto/md5"
   "fmt"
   "io"
   "log"
   "os"
)

func printUsage() {
   fmt.Println("Usage: " + os.Args[0] + " <filename>")
   fmt.Println("Example: " + os.Args[0] + " diskimage.iso")
}

func checkArgs() string {
   if len(os.Args) < 2 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1]
}

func main() {
   filename := checkArgs()

   // Open file for reading
   file, err := os.Open(filename)
   if err != nil {
      log.Fatal(err)
   }
   defer file.Close()

   // Create new hasher, which is a writer interface
   hasher := md5.New()

   // Default buffer size for copying is 32*1024 or 32kb per copy
   // Use io.CopyBuffer() if you want to specify the buffer to use
   // It will write 32kb at a time to the digest/hash until EOF
   // The hasher implements a Write() function making it satisfy
   // the writer interface. The Write() function performs the digest
   // at the time the data is copied/written to it. It digests
   // and processes the hash one chunk at a time as it is received.
   _, err = io.Copy(hasher, file)
   if err != nil {
      log.Fatal(err)
   }

   // Now get the final sum or checksum.
   // We pass nil to the Sum() function because
   // we already copied the bytes via the Copy to the
   // writer interface and don't need to pass any new bytes
   checksum := hasher.Sum(nil)

   fmt.Printf("Md5 checksum: %x\n", checksum)
}
```

# 安全存储密码

现在我们知道如何哈希，我们可以谈论安全地存储密码。哈希是保护密码的重要因素。其他重要因素是加盐，使用密码学强哈希函数，以及可选使用**基于哈希的消息认证码**（HMAC），这些都在哈希算法中添加了一个额外的秘密密钥。

HMAC 是一个使用秘钥的附加层；因此，即使攻击者获得了带有盐的哈希密码数据库，没有秘密密钥，他们仍然会很难破解它们。秘密密钥应该存储在一个单独的位置，比如环境变量，而不是与哈希密码和盐一起存储在数据库中。

这个示例应用程序的用途有限。将其用作您自己应用程序的参考。

```go
package main

import (
   "crypto/hmac"
   "crypto/rand"
   "crypto/sha256"
   "encoding/base64"
   "encoding/hex"
   "fmt"
   "io"
   "os"
)

func printUsage() {
   fmt.Println("Usage: " + os.Args[0] + " <password>")
   fmt.Println("Example: " + os.Args[0] + " Password1!")
}

func checkArgs() string {
   if len(os.Args) < 2 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1]
}

// secretKey should be unique, protected, private,
// and not hard-coded like this. Store in environment var
// or in a secure configuration file.
// This is an arbitrary key that should only be used 
// for example purposes.
var secretKey = "neictr98y85klfgneghre"

// Create a salt string with 32 bytes of crypto/rand data
func generateSalt() string {
   randomBytes := make([]byte, 32)
   _, err := rand.Read(randomBytes)
   if err != nil {
      return ""
   }
   return base64.URLEncoding.EncodeToString(randomBytes)
}

// Hash a password with the salt
func hashPassword(plainText string, salt string) string {
   hash := hmac.New(sha256.New, []byte(secretKey))
   io.WriteString(hash, plainText+salt)
   hashedValue := hash.Sum(nil)
   return hex.EncodeToString(hashedValue)
}

func main() {
   // Get the password from command line argument
   password := checkArgs()
   salt := generateSalt()
   hashedPassword := hashPassword(password, salt)
   fmt.Println("Password: " + password)
   fmt.Println("Salt: " + salt)
   fmt.Println("Hashed password: " + hashedPassword)
}
```

# 加密

加密与哈希不同，因为它是可逆的，原始消息可以被恢复。有对称加密方法使用密码或共享密钥进行加密和解密。还有非对称加密算法使用公钥和私钥对。AES 是对称加密的一个例子，用于加密 ZIP 文件、PDF 文件或整个文件系统。RSA 是非对称加密的一个例子，用于 SSL、SSH 密钥和 PGP。

# 密码学安全伪随机数生成器（CSPRNG）

`math`和`rand`包提供的随机性不如`crypto/rand`包。不要将`math/rand`用于加密应用。

在[`golang.org/pkg/crypto/rand/`](https://golang.org/pkg/crypto/rand/)上了解更多关于 Go 的`crypto/rand`包的信息。

以下示例将演示如何生成随机字节、随机整数或任何其他有符号或无符号类型的整数：

```go
package main

import (
   "crypto/rand"
   "encoding/binary"
   "fmt"
   "log"
   "math"
   "math/big"
)

func main() {
   // Generate a random int
   limit := int64(math.MaxInt64) // Highest random number allowed
   randInt, err := rand.Int(rand.Reader, big.NewInt(limit))
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println("Random int value: ", randInt)

   // Alternatively, you could generate the random bytes
   // and turn them into the specific data type needed.
   // binary.Read() will only read enough bytes to fill the data type
   var number uint32
   err = binary.Read(rand.Reader, binary.BigEndian, &number)
   if err != nil {
      log.Fatal(err)
   }
   fmt.Println("Random uint32 value: ", number)

   // Or just generate a random byte slice
   numBytes := 4
   randomBytes := make([]byte, numBytes)
   rand.Read(randomBytes)
   fmt.Println("Random byte values: ", randomBytes)
}
```

# 对称加密

对称加密是指使用相同的密钥或密码来加密和解密数据。高级加密标准，也称为 AES 或 Rijndael，是 NIST 在 2001 年制定的对称加密算法标准。

数据加密标准（DES）是另一种对称加密算法，比 AES 更老且不太安全。除非有特定要求或规范，否则不应该使用 DES 而不是 AES。Go 标准库包括 AES 和 DES 包。

# AES

该程序将使用一个 32 字节（256 位）的密码来加密和解密文件。

在生成密钥、加密或解密时，输出通常发送到`STDOUT`或终端。您可以使用`>`运算符将输出轻松重定向到文件或另一个程序。请参考用法模式以获取示例。如果需要将密钥或加密数据存储为 ASCII 编码的字符串，请使用 base64 编码。

在这个示例中的某个时候，您会看到消息被分成两部分，IV 和密文。初始化向量或 IV 是一个随机值，它被预置到实际加密的消息之前。每次使用 AES 加密消息时，都会生成并使用一个随机值作为加密的一部分。这个随机值被称为一次性号码，简单地意味着只使用一次的数字。

为什么要创建这些一次性值？特别是如果它们不保密，并且直接放在加密消息的前面，它有什么作用？随机 IV 的使用方式类似于盐。它主要用于当相同的消息被重复加密时，每次的密文都是不同的。

要使用**Galois/Counter Mode**（GCM）而不是 CFB，请更改加密和解密方法。GCM 具有更好的性能和效率，因为它允许并行处理。在[`en.wikipedia.org/wiki/Galois/Counter_Mode`](https://en.wikipedia.org/wiki/Galois/Counter_Mode)上了解更多关于 GCM 的信息。

从 AES 密码开始，并调用`cipher.NewCFBEncrypter(block, iv)`。然后根据您是否需要加密或解密，您将使用您生成的 nonce 调用`.Seal()`，或者调用`.Open()`并传递分离的 nonce 和密文：

```go
package main

import (
   "crypto/aes"
   "crypto/cipher"
   "crypto/rand"
   "fmt"
   "io"
   "io/ioutil"
   "os"
   "log"
)

func printUsage() {
   fmt.Printf(os.Args[0] + `

Encrypt or decrypt a file using AES with a 256-bit key file.
This program can also generate 256-bit keys.

Usage:
  ` + os.Args[0] + ` [-h|--help]
  ` + os.Args[0] + ` [-g|--genkey]
  ` + os.Args[0] + ` <keyFile> <file> [-d|--decrypt]

Examples:
  # Generate a 32-byte (256-bit) key
  ` + os.Args[0] + ` --genkey

  # Encrypt with secret key. Output to STDOUT
  ` + os.Args[0] + ` --genkey > secret.key

  # Encrypt message using secret key. Output to ciphertext.dat
  ` + os.Args[0] + ` secret.key message.txt > ciphertext.dat

  # Decrypt message using secret key. Output to STDOUT
  ` + os.Args[0] + ` secret.key ciphertext.dat -d

  # Decrypt message using secret key. Output to message.txt
  ` + os.Args[0] + ` secret.key ciphertext.dat -d > cleartext.txt
`)
}

// Check command-line arguments.
// If the help or generate key functions are chosen
// they are run and then the program exits
// otherwise it returns keyFile, file, decryptFlag.
func checkArgs() (string, string, bool) {
   if len(os.Args) < 2  || len(os.Args) > 4 {
      printUsage()
      os.Exit(1)
   }

   // One arg provided
   if len(os.Args) == 2 {
      // Only -h, --help and --genkey are valid one-argument uses
      if os.Args[1] == "-h" || os.Args[1] == "--help" {
         printUsage() // Print help text
         os.Exit(0) // Exit gracefully no error
      }
      if os.Args[1] == "-g" || os.Args[1] == "--genkey" {
         // Generate a key and print to STDOUT
         // User should redirect output to a file if needed
         key := generateKey()
         fmt.Printf(string(key[:])) // No newline
         os.Exit(0) // Exit gracefully
      }
   }

   // The only use options left is
   // encrypt <keyFile> <file> [-d|--decrypt]
   // If there are only 2 args provided, they must be the
   // keyFile and file without a decrypt flag.
   if len(os.Args) == 3 {
      // keyFile, file, decryptFlag
      return os.Args[1], os.Args[2], false 
   }
   // If 3 args are provided,
   // check that the last one is -d or --decrypt
   if len(os.Args) == 4 {
      if os.Args[3] != "-d" && os.Args[3] != "--decrypt" {
         fmt.Println("Error: Unknown usage.")
         printUsage()
         os.Exit(1) // Exit with error code
      }
      return os.Args[1], os.Args[2], true
   }
    return "", "", false // Default blank return
}

func generateKey() []byte {
   randomBytes := make([]byte, 32) // 32 bytes, 256 bit
   numBytesRead, err := rand.Read(randomBytes)
   if err != nil {
      log.Fatal("Error generating random key.", err)
   }
   if numBytesRead != 32 {
      log.Fatal("Error generating 32 random bytes for key.")
   }
   return randomBytes
}

// AES encryption
func encrypt(key, message []byte) ([]byte, error) {
   // Initialize block cipher
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }

   // Create the byte slice that will hold encrypted message
   cipherText := make([]byte, aes.BlockSize+len(message))

   // Generate the Initialization Vector (IV) nonce
   // which is stored at the beginning of the byte slice
   // The IV is the same length as the AES blocksize
   iv := cipherText[:aes.BlockSize]
   _, err = io.ReadFull(rand.Reader, iv)
   if err != nil {
      return nil, err
   }

   // Choose the block cipher mode of operation
   // Using the cipher feedback (CFB) mode here.
   // CBCEncrypter also available.
   cfb := cipher.NewCFBEncrypter(block, iv)
   // Generate the encrypted message and store it
   // in the remaining bytes after the IV nonce
   cfb.XORKeyStream(cipherText[aes.BlockSize:], message)

   return cipherText, nil
}

// AES decryption
func decrypt(key, cipherText []byte) ([]byte, error) {
   // Initialize block cipher
   block, err := aes.NewCipher(key)
   if err != nil {
      return nil, err
   }

   // Separate the IV nonce from the encrypted message bytes
   iv := cipherText[:aes.BlockSize]
   cipherText = cipherText[aes.BlockSize:]

   // Decrypt the message using the CFB block mode
   cfb := cipher.NewCFBDecrypter(block, iv)
   cfb.XORKeyStream(cipherText, cipherText)

   return cipherText, nil
}

func main() {
   // if generate key flag, just output a key to stdout and exit
   keyFile, file, decryptFlag := checkArgs()

   // Load key from file
   keyFileData, err := ioutil.ReadFile(keyFile)
   if err != nil {
      log.Fatal("Unable to read key file contents.", err)
   }

   // Load file to be encrypted or decrypted
   fileData, err := ioutil.ReadFile(file)
   if err != nil {
      log.Fatal("Unable to read key file contents.", err)
   }

   // Perform encryption unless the decryptFlag was provided
   // Outputs to STDOUT. User can redirect output to file.
   if decryptFlag {
      message, err := decrypt(keyFileData, fileData)
      if err != nil {
         log.Fatal("Error decrypting. ", err)
      }
      fmt.Printf("%s", message)
   } else {
      cipherText, err := encrypt(keyFileData, fileData)
      if err != nil {
         log.Fatal("Error encrypting. ", err)
      }
      fmt.Printf("%s", cipherText)
   }
}
```

# 非对称加密

当每个方都有两个密钥时，就是非对称的。每一方都需要一个公钥和私钥对。非对称加密算法包括 RSA，DSA 和 ECDSA。Go 标准库中有 RSA，DSA 和 ECDSA 的包。一些使用非对称加密的应用包括**安全外壳**（**SSH**），**安全套接字层**（**SSL**）和**很好的隐私**（**PGP**）。

SSL 是由网景公司最初开发的**安全套接字层**，版本 2 于 1995 年公开发布。它用于加密服务器和客户端之间的通信，提供机密性，完整性和认证。**TLS**，或**传输层安全**，是 SSL 的新版本，1.2 版于 2008 年作为 RFC 5246 定义。Go 的 TLS 包并未完全实现规范，但实现了主要部分。了解有关 Go 的`crypto/tls`包的更多信息，请访问[`golang.org/pkg/crypto/tls/`](https://golang.org/pkg/crypto/tls/)。

您只能加密小于密钥大小的东西，这通常是 2048 位。由于这种大小限制，非对称 RSA 加密不适用于加密整个文档，这些文档很容易超过 2048 位或 256 字节。另一方面，例如 AES 的对称加密可以加密大型文档，但它需要双方共享的密钥。TLS/SSL 使用非对称和对称加密的组合。初始连接和握手使用每一方的公钥和私钥进行非对称加密。一旦建立连接，将生成并共享一个共享密钥。一旦双方都知道共享密钥，非对称加密将被丢弃，其余的通信将使用对称加密，例如使用共享密钥的 AES。

这里的示例将使用 RSA 密钥。我们将介绍如何生成自己的公钥和私钥，并将它们保存为 PEM 编码的文件，数字签名消息和验证签名。在下一节中，我们将使用这些密钥创建自签名证书并建立安全的 TLS 连接。

# 生成公钥和私钥对

在使用非对称加密之前，您需要一个公钥和私钥对。私钥必须保密并且不与任何人共享。公钥应与他人共享。

**RSA**（**Rivest-Shamir-Adleman**）和**ECDSA**（**椭圆曲线数字签名算法**）算法在 Go 标准库中可用。ECDSA 被认为更安全，但 RSA 是 SSL 证书中最常用的算法。

您可以选择对私钥进行密码保护。您不需要这样做，但这是额外的安全层。由于私钥非常敏感，建议您使用密码保护。

如果要使用对称加密算法（例如 AES）对私钥文件进行密码保护，可以使用一些标准库函数。您将需要的主要函数是`x509.EncryptPEMBlock()`，`x509.DecryptPEMBlock()`和`x509.IsEncryptedPEMBlock()`。

要执行使用 OpenSSL 生成私钥和公钥文件的等效操作，请使用以下内容：

```go
# Generate the private key  
openssl genrsa -out priv.pem 2048 
# Extract the public key from the private key 
openssl rsa -in priv.pem -pubout -out public.pem 
```

您可以在[`golang.org/pkg/encoding/pem/`](https://golang.org/pkg/encoding/pem/)了解有关 Go 的 PEM 编码的更多信息。参考以下代码：

```go
package main

import (
   "crypto/rand"
   "crypto/rsa"
   "crypto/x509"
   "encoding/pem"
   "fmt"
   "log"
   "os"
   "strconv"
)

func printUsage() {
   fmt.Printf(os.Args[0] + `

Generate a private and public RSA keypair and save as PEM files.
If no key size is provided, a default of 2048 is used.

Usage:
  ` + os.Args[0] + ` <private_key_filename> <public_key_filename>       [keysize]

Examples:
  # Store generated private and public key in privkey.pem and   pubkey.pem
  ` + os.Args[0] + ` priv.pem pub.pem
  ` + os.Args[0] + ` priv.pem pub.pem 4096`)
}

func checkArgs() (string, string, int) {
   // Too many or too few arguments
   if len(os.Args) < 3 || len(os.Args) > 4 {
      printUsage()
      os.Exit(1)
   }

   defaultKeySize := 2048

   // If there are 2 args provided, privkey and pubkey filenames
   if len(os.Args) == 3 {
      return os.Args[1], os.Args[2], defaultKeySize
   }

   // If 3 args provided, privkey, pubkey, keysize
   if len(os.Args) == 4 {
      keySize, err := strconv.Atoi(os.Args[3])
      if err != nil {
         printUsage()
         fmt.Println("Invalid keysize. Try 1024 or 2048.")
         os.Exit(1)
      }
      return os.Args[1], os.Args[2], keySize
   }

   return "", "", 0 // Default blank return catch-all
}

// Encode the private key as a PEM file
// PEM is a base-64 encoding of the key
func getPrivatePemFromKey(privateKey *rsa.PrivateKey) *pem.Block {
   encodedPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
   var privatePem = &pem.Block {
      Type: "RSA PRIVATE KEY",
      Bytes: encodedPrivateKey,
   }
   return privatePem
}

// Encode the public key as a PEM file
func generatePublicPemFromKey(publicKey rsa.PublicKey) *pem.Block {
   encodedPubKey, err := x509.MarshalPKIXPublicKey(&publicKey)
   if err != nil {
      log.Fatal("Error marshaling PKIX pubkey. ", err)
   }

   // Create a public PEM structure with the data
   var publicPem = &pem.Block{
      Type:  "PUBLIC KEY",
      Bytes: encodedPubKey,
   }
   return publicPem
}

func savePemToFile(pemBlock *pem.Block, filename string) {
   // Save public pem to file
   publicPemOutputFile, err := os.Create(filename)
   if err != nil {
      log.Fatal("Error opening pubkey output file. ", err)
   }
   defer publicPemOutputFile.Close()

   err = pem.Encode(publicPemOutputFile, pemBlock)
   if err != nil {
      log.Fatal("Error encoding public PEM. ", err)
   }
}

// Generate a public and private RSA key in PEM format
func main() {
   privatePemFilename, publicPemFilename, keySize := checkArgs()

   // Generate private key
   privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
   if err != nil {
      log.Fatal("Error generating private key. ", err)
   }

   // Encode keys to PEM format
   privatePem := getPrivatePemFromKey(privateKey)
   publicPem := generatePublicPemFromKey(privateKey.PublicKey)

   // Save the PEM output to files
   savePemToFile(privatePem, privatePemFilename)
   savePemToFile(publicPem, publicPemFilename)

   // Print the public key to STDOUT for convenience
   fmt.Printf("%s", pem.EncodeToMemory(publicPem))
}
```

# 数字签名消息

签署消息的目的是让接收者知道消息来自正确的人。要签署消息，首先生成消息的哈希，然后使用您的私钥加密哈希。加密的哈希就是您的签名。

接收者将解密你的签名以获得你提供的原始哈希，然后他们将对消息进行哈希处理，看看他们自己从消息中生成的哈希是否与签名的解密值匹配。如果匹配，接收者就知道签名是有效的，并且来自正确的发送者。

请注意，签署一条消息实际上并不加密消息。如果需要，你仍然需要在发送消息之前对消息进行加密。如果你想公开发布你的消息，你可能不想加密消息本身。其他人仍然可以使用签名来验证发布消息的人。

只有小于 RSA 密钥大小的消息才能被签名。因为 SHA-256 哈希总是具有相同的输出长度，我们可以确保它在可接受的大小限制内。在这个例子中，我们使用了 RSA PKCS#1 v1.5 标准签名和 SHA-256 哈希方法。

Go 编程语言提供了核心包中的函数来处理签名和验证。主要函数是`rsa.VerifyPKCS1v5`。这个函数负责对消息进行哈希处理，然后用私钥对其进行加密。

以下程序将接收一条消息和一个私钥，并将签名输出到`STDOUT`：

```go
package main

import (
   "crypto"
   "crypto/rand"
   "crypto/rsa"
   "crypto/sha256"
   "crypto/x509"
   "encoding/pem"
   "fmt"
   "io/ioutil"
   "log"
   "os"
)

func printUsage() {
   fmt.Println(os.Args[0] + `

Cryptographically sign a message using a private key.
Private key should be a PEM encoded RSA key.
Signature is generated using SHA256 hash.
Output signature is stored in filename provided.

Usage:
  ` + os.Args[0] + ` <privateKeyFilename> <messageFilename>   <signatureFilename>

Example:
  # Use priv.pem to encrypt msg.txt and output to sig.txt.256
  ` + os.Args[0] + ` priv.pem msg.txt sig.txt.256
`)
}

// Get arguments from command line
func checkArgs() (string, string, string) {
   // Need exactly 3 arguments provided
   if len(os.Args) != 4 {
      printUsage()
      os.Exit(1)
   }

   // Private key file name and message file name
   return os.Args[1], os.Args[2], os.Args[3]
}

// Cryptographically sign a message= creating a digital signature
// of the original message. Uses SHA-256 hashing.
func signMessage(privateKey *rsa.PrivateKey, message []byte) []byte {
   hashed := sha256.Sum256(message)

   signature, err := rsa.SignPKCS1v15(
      rand.Reader,
      privateKey,
      crypto.SHA256,
      hashed[:],
   )
   if err != nil {
      log.Fatal("Error signing message. ", err)
   }

   return signature
}

// Load the message that will be signed from file
func loadMessageFromFile(messageFilename string) []byte {
   fileData, err := ioutil.ReadFile(messageFilename)
   if err != nil {
      log.Fatal(err)
   }
   return fileData
}

// Load the RSA private key from a PEM encoded file
func loadPrivateKeyFromPemFile(privateKeyFilename string) *rsa.PrivateKey {
   // Quick load file to memory
   fileData, err := ioutil.ReadFile(privateKeyFilename)
   if err != nil {
      log.Fatal(err)
   }

   // Get the block data from the PEM encoded file
   block, _ := pem.Decode(fileData)
   if block == nil || block.Type != "RSA PRIVATE KEY" {
      log.Fatal("Unable to load a valid private key.")
   }

   // Parse the bytes and put it in to a proper privateKey struct
   privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      log.Fatal("Error loading private key.", err)
   }

   return privateKey
}

// Save data to file
func writeToFile(filename string, data []byte) error {
   // Open a new file for writing only
   file, err := os.OpenFile(
      filename,
      os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
      0666,
   )
   if err != nil {
      return err
   }
   defer file.Close()

   // Write bytes to file
   _, err = file.Write(data)
   if err != nil {
      return err
   }

   return nil
}

// Sign a message using a private RSA key
func main() {
   // Get arguments from command line
   privateKeyFilename, messageFilename, sigFilename := checkArgs()

   // Load message and private key files from disk
   message := loadMessageFromFile(messageFilename)
   privateKey := loadPrivateKeyFromPemFile(privateKeyFilename)

   // Cryptographically sign the message
   signature := signMessage(privateKey, message)

   // Output to file
   writeToFile(sigFilename, signature)
}
```

# 验证签名

在前面的例子中，我们学习了如何为接收者创建一条消息的签名以进行验证。现在让我们来看看验证签名的过程。

如果你收到一条消息和一个签名，你必须首先使用发送者的公钥解密签名。然后对原始消息进行哈希处理，看看你的哈希是否与解密的签名匹配。如果你的哈希与解密的签名匹配，那么你可以确定发送者是拥有与你用来验证的公钥配对的私钥的人。

为了验证签名，我们使用了与创建签名相同的算法（RSA PKCS#1 v1.5 with SHA-256）。

这个例子需要两个命令行参数。第一个参数是创建签名的人的公钥，第二个参数是带有签名的文件。要创建一个签名文件，可以使用前面例子中的签名程序，并将输出重定向到一个文件中。

与前一节类似，Go 语言在标准库中有一个用于验证签名的函数。我们可以使用`rsa.VerifyPKCS1v5()`来比较消息哈希与签名的解密值，并查看它们是否匹配：

```go
package main

import (
   "crypto"
   "crypto/rsa"
   "crypto/sha256"
   "crypto/x509"
   "encoding/pem"
   "fmt"
   "io/ioutil"
   "log"
   "os"
)

func printUsage() {
    fmt.Println(os.Args[0] + `

Verify an RSA signature of a message using SHA-256 hashing.
Public key is expected to be a PEM file.

Usage:
  ` + os.Args[0] + ` <publicKeyFilename> <signatureFilename> <messageFilename>

Example:
  ` + os.Args[0] + ` pubkey.pem signature.txt message.txt
`)
}

// Get arguments from command line
func checkArgs() (string, string, string) {
   // Expect 3 arguments: pubkey, signature, message file names
   if len(os.Args) != 4 {
      printUsage()
      os.Exit(1)
   }

   return os.Args[1], os.Args[2], os.Args[3]
}

// Returns bool whether signature was verified
func verifySignature(
   signature []byte,
   message []byte,
   publicKey *rsa.PublicKey) bool {

   hashedMessage := sha256.Sum256(message)

   err := rsa.VerifyPKCS1v15(
      publicKey,
      crypto.SHA256,
      hashedMessage[:],
      signature,
   )

   if err != nil {
      log.Println(err)
      return false
   }
   return true // If no error, match.
}

// Load file to memory
func loadFile(filename string) []byte {
   fileData, err := ioutil.ReadFile(filename)
   if err != nil {
      log.Fatal(err)
   }
   return fileData
}

// Load a public RSA key from a PEM encoded file
func loadPublicKeyFromPemFile(publicKeyFilename string) *rsa.PublicKey {
   // Quick load file to memory
   fileData, err := ioutil.ReadFile(publicKeyFilename)
   if err != nil {
      log.Fatal(err)
   }

   // Get the block data from the PEM encoded file
   block, _ := pem.Decode(fileData)
   if block == nil || block.Type != "PUBLIC KEY" {
      log.Fatal("Unable to load valid public key. ")
   }

   // Parse the bytes and store in a public key format
   publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
   if err != nil {
      log.Fatal("Error loading public key. ", err)
   }

   return publicKey.(*rsa.PublicKey) // Cast interface to PublicKey
}

// Verify a cryptographic signature using RSA PKCS#1 v1.5 with SHA-256
// and a PEM encoded PKIX public key.
func main() {
   // Parse command line arguments
   publicKeyFilename, signatureFilename, messageFilename :=   
      checkArgs()

   // Load all the files from disk
   publicKey := loadPublicKeyFromPemFile(publicKeyFilename)
   signature := loadFile(signatureFilename)
   message := loadFile(messageFilename)

   // Verify signature
   valid := verifySignature(signature, message, publicKey)

   if valid {
      fmt.Println("Signature verified.")
   } else {
      fmt.Println("Signature could not be verified.")
   }
}
```

# TLS

我们通常不会使用 RSA 加密整个消息，因为它只能加密小于密钥大小的消息。解决这个问题的方法通常是从使用 RSA 密钥加密的小消息开始通信。当它们建立了一个安全通道后，它们可以安全地交换一个共享密钥，用于对其余消息进行对称加密，而不受大小限制。这是 SSL 和 TLS 用来建立安全通信的方法。握手过程负责协商在生成和共享对称密钥时将使用哪些加密算法。

# 生成自签名证书

要使用 Go 创建自签名证书，你需要一个公钥和私钥对。x509 包中有一个用于创建证书的函数。它需要公钥和私钥以及一个包含所有信息的模板证书。由于我们是自签名的，模板证书也将用作执行签名的父证书。

每个应用程序可以以不同的方式处理自签名证书。有些应用程序会在证书是自签名时警告你，有些会拒绝接受它，而其他一些则会在不警告你的情况下使用它。当你编写自己的应用程序时，你将不得不决定是否要验证证书或接受自签名证书。

重要的函数是`x509.CreateCertificate()`，在[`golang.org/pkg/crypto/x509/#CreateCertificate`](https://golang.org/pkg/crypto/x509/#CreateCertificate)中有引用。以下是函数签名：

```go
func CreateCertificate (rand io.Reader, template, parent *Certificate, pub, 
   priv interface{}) (cert []byte, err error)
```

这个例子将使用私钥生成一个由它签名的证书，并将其保存为 PEM 格式的文件。一旦你创建了一个自签名证书，你就可以将该证书与私钥一起使用，运行安全的 TLS 套接字监听器和 Web 服务器。

为了简洁起见，这个例子将证书所有者信息和主机名 IP 硬编码为 localhost。这对于在本地机器上进行测试已经足够了。

根据需要修改这些内容，自定义值，通过命令行参数输入，或者使用标准输入动态获取用户的值，如下面的代码块所示：

```go
package main

import (
   "crypto/rand"
   "crypto/rsa"
   "crypto/x509/pkix"
   "crypto/x509"
   "encoding/pem"
   "fmt"
   "io/ioutil"
   "log"
   "math/big"
   "net"
   "os"
   "time"
)

func printUsage() {
   fmt.Println(os.Args[0] + ` - Generate a self signed TLS certificate

Usage:
  ` + os.Args[0] + ` <privateKeyFilename> <certOutputFilename> [-ca|--cert-authority]

Example:
  ` + os.Args[0] + ` priv.pem cert.pem
  ` + os.Args[0] + ` priv.pem cacert.pem -ca
`)
}

func checkArgs() (string, string, bool) {
   if len(os.Args) < 3 || len(os.Args) > 4 {
      printUsage()
      os.Exit(1)
   }

   // See if the last cert authority option was passed
   isCA := false // Default
   if len(os.Args) == 4 {
      if os.Args[3] == "-ca" || os.Args[3] == "--cert-authority" {
         isCA = true
      }
   }

   // Private key filename, cert output filename, is cert authority
   return os.Args[1], os.Args[2], isCA
}

func setupCertificateTemplate(isCA bool) x509.Certificate {
   // Set valid time frame to start now and end one year from now
   notBefore := time.Now()
   notAfter := notBefore.Add(time.Hour * 24 * 365) // 1 year/365 days

   // Generate secure random serial number
   serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
   randomNumber, err := rand.Int(rand.Reader, serialNumberLimit)
   if err != nil {
      log.Fatal("Error generating random serial number. ", err)
   }

   nameInfo := pkix.Name{
      Organization: []string{"My Organization"},
      CommonName: "localhost",
      OrganizationalUnit: []string{"My Business Unit"},
      Country:        []string{"US"}, // 2-character ISO code
      Province:       []string{"Texas"}, // State
      Locality:       []string{"Houston"}, // City
   }

   // Create the certificate template
   certTemplate := x509.Certificate{
      SerialNumber: randomNumber,
      Subject: nameInfo,
      EmailAddresses: []string{"test@localhost"},
      NotBefore: notBefore,
      NotAfter: notAfter,
      KeyUsage: x509.KeyUsageKeyEncipherment |   
         x509.KeyUsageDigitalSignature,
      // For ExtKeyUsage, default to any, but can specify to use
      // only as server or client authentication, code signing, etc
      ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
      BasicConstraintsValid: true,
      IsCA: false,
   }

   // To create a certificate authority that can sign cert signing   
   // requests, set these
   if isCA {
      certTemplate.IsCA = true
      certTemplate.KeyUsage = certTemplate.KeyUsage |  
         x509.KeyUsageCertSign
   }

   // Add any IP addresses and hostnames covered by this cert
   // This example only covers localhost
   certTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
   certTemplate.DNSNames = []string{"localhost", "localhost.local"}

   return certTemplate
}

// Load the RSA private key from a PEM encoded file
func loadPrivateKeyFromPemFile(privateKeyFilename string) *rsa.PrivateKey {
   // Quick load file to memory
   fileData, err := ioutil.ReadFile(privateKeyFilename)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   // Get the block data from the PEM encoded file
   block, _ := pem.Decode(fileData)
   if block == nil || block.Type != "RSA PRIVATE KEY" {
      log.Fatal("Unable to load a valid private key.")
   }

   // Parse the bytes and put it in to a proper privateKey struct
   privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      log.Fatal("Error loading private key. ", err)
   }

   return privateKey
}

// Save the certificate as a PEM encoded file
func writeCertToPemFile(outputFilename string, derBytes []byte ) {
   // Create a PEM from the certificate
   certPem := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}

   // Open file for writing
   certOutfile, err := os.Create(outputFilename)
   if err != nil {
      log.Fatal("Unable to open certificate output file. ", err)
   }
   pem.Encode(certOutfile, certPem)
   certOutfile.Close()
}

// Create a self-signed TLS/SSL certificate for localhost 
// with an RSA private key
func main() {
   privPemFilename, certOutputFilename, isCA := checkArgs()

   // Private key of signer - self signed means signer==signee
   privKey := loadPrivateKeyFromPemFile(privPemFilename)

   // Public key of signee. Self signing means we are the signer and    
   // the signee so we can just pull our public key from our private key
   pubKey := privKey.PublicKey

   // Set up all the certificate info
   certTemplate := setupCertificateTemplate(isCA)

   // Create (and sign with the priv key) the certificate
   certificate, err := x509.CreateCertificate(
      rand.Reader,
      &certTemplate,
      &certTemplate,
      &pubKey,
      privKey,
   )
   if err != nil {
      log.Fatal("Failed to create certificate. ", err)
   }

   // Format the certificate as a PEM and write to file
   writeCertToPemFile(certOutputFilename, certificate)
}
```

# 创建证书签名请求

如果你不想创建自签名证书，你必须创建一个证书签名请求，并让受信任的证书颁发机构对其进行签名。你可以通过调用`x509.CreateCertificateRequest()`并传递一个带有私钥的`x509.CertificateRequest`对象来创建一个证书请求。

使用 OpenSSL 进行等效操作如下：

```go
# Create CSR 
openssl req -new -key priv.pem -out csr.pem 
# View details to verify request was created properly 
openssl req -verify -in csr.pem -text -noout 
```

这个例子演示了如何创建证书签名请求：

```go
package main

import (
   "crypto/rand"
   "crypto/rsa"
   "crypto/x509"
   "crypto/x509/pkix"
   "encoding/pem"
   "fmt"
   "io/ioutil"
   "log"
   "net"
   "os"
)

func printUsage() {
   fmt.Println(os.Args[0] + ` - Create a certificate signing request  
   with a private key.

Private key is expected in PEM format. Certificate valid for localhost only.
Certificate signing request is created using the SHA-256 hash.

Usage:
  ` + os.Args[0] + ` <privateKeyFilename> <csrOutputFilename>

Example:
  ` + os.Args[0] + ` priv.pem csr.pem
`)
}

func checkArgs() (string, string) {
   if len(os.Args) != 3 {
      printUsage()
      os.Exit(1)
   }

   // Private key filename, cert signing request output filename
   return os.Args[1], os.Args[2]
}

// Load the RSA private key from a PEM encoded file
func loadPrivateKeyFromPemFile(privateKeyFilename string) *rsa.PrivateKey {
   // Quick load file to memory
   fileData, err := ioutil.ReadFile(privateKeyFilename)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   // Get the block data from the PEM encoded file
   block, _ := pem.Decode(fileData)
   if block == nil || block.Type != "RSA PRIVATE KEY" {
      log.Fatal("Unable to load a valid private key.")
   }

   // Parse the bytes and put it in to a proper privateKey struct
   privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
   if err != nil {
      log.Fatal("Error loading private key.", err)
   }

   return privateKey
}

// Create a CSR PEM and save to file
func saveCSRToPemFile(csr []byte, filename string) {
   csrPem := &pem.Block{
      Type:  "CERTIFICATE REQUEST",
      Bytes: csr,
   }
   csrOutfile, err := os.Create(filename)
   if err != nil {
      log.Fatal("Error opening "+filename+" for saving. ", err)
   }
   pem.Encode(csrOutfile, csrPem)
}

// Create a certificate signing request with a private key 
// valid for localhost
func main() {
   // Load parameters
   privKeyFilename, csrOutFilename := checkArgs()
   privKey := loadPrivateKeyFromPemFile(privKeyFilename)

   // Prepare information about organization the cert will belong to
   nameInfo := pkix.Name{
      Organization:       []string{"My Organization Name"},
      CommonName:         "localhost",
      OrganizationalUnit: []string{"Business Unit Name"},
      Country:            []string{"US"}, // 2-character ISO code
      Province:           []string{"Texas"},
      Locality:           []string{"Houston"}, // City
   }

   // Prepare CSR template
   csrTemplate := x509.CertificateRequest{
      Version:            2, // Version 3, zero-indexed values
      SignatureAlgorithm: x509.SHA256WithRSA,
      PublicKeyAlgorithm: x509.RSA,
      PublicKey:          privKey.PublicKey,
      Subject:            nameInfo,

      // Subject Alternate Name values.
      DNSNames:       []string{"Business Unit Name"},
      EmailAddresses: []string{"test@localhost"},
      IPAddresses:    []net.IP{},
   }

   // Create the CSR based off the template
   csr, err := x509.CreateCertificateRequest(rand.Reader,  
      &csrTemplate, privKey)
   if err != nil {
      log.Fatal("Error creating certificate signing request. ", err)
   }
   saveCSRToPemFile(csr, csrOutFilename)
}
```

# 签署证书请求

在前面的例子中，当生成自签名证书时，我们已经演示了创建签名证书的过程。在自签名的例子中，我们只是使用了与签名者相同的证书模板。因此，没有单独的代码示例。唯一的区别是进行签名的父证书或要签名的模板应该被替换为不同的证书。

这是`x509.CreateCertificate()`的函数定义：

```go
func CreateCertificate(rand io.Reader, template, parent *Certificate, pub, 
   priv interface{}) (cert []byte, err error)
```

在自签名的例子中，模板和父证书是同一个对象。要签署证书请求，创建一个新的证书对象，并用签名请求中的信息填充字段。将新证书作为模板，使用签名者的证书作为父证书。`pub`参数是受让人的公钥，`priv`参数是签名者的私钥。签名者是证书颁发机构，受让人是请求者。你可以在[`golang.org/pkg/crypto/x509/#CreateCertificate`](https://golang.org/pkg/crypto/x509/#CreateCertificate)了解更多关于这个函数的信息。

`X509.CreateCertificate()`的参数如下：

+   `rand`：这是密码学安全的伪随机数生成器

+   `template`：这是使用 CSR 中的信息填充的证书模板

+   `parent`：这是签名者的证书

+   `pub`：这是受让人的公钥

+   `priv`：这是签名者的私钥

使用 OpenSSL 进行等效操作如下：

```go
# Create signed certificate using
# the CSR, CA certificate, and private key 
openssl x509 -req -in csr.pem -CA cacert.pem \
-CAkey capriv.pem -CAcreateserial \
-out cert.pem -sha256
# Print info about cert 
openssl x509 -in cert.pem -text -noout  
```

# TLS 服务器

你可以像设置普通套接字连接一样设置监听器，但是加密。只需调用 TLS 的`Listen()`函数，并提供你的证书和私钥。使用前面示例中生成的证书和密钥将起作用。

以下程序将创建一个 TLS 服务器，并回显接收到的任何数据，然后关闭连接。服务器不需要或验证客户端证书，但是用于进行验证的代码被注释掉，以供参考，以防你想要使用证书对客户端进行身份验证：

```go
package main

import (
   "bufio"
   "crypto/tls"
   "fmt"
   "log"
   "net"
   "os"
)

func printUsage() {
   fmt.Println(os.Args[0] + ` - Start a TLS echo server

Server will echo one message received back to client.
Provide a certificate and private key file in PEM format.
Host string in the format: hostname:port

Usage:
  ` + os.Args[0] + ` <certFilename> <privateKeyFilename> <hostString>

Example:
  ` + os.Args[0] + ` cert.pem priv.pem localhost:9999
`)
}

func checkArgs() (string, string, string) {
  if len(os.Args) != 4 {
     printUsage()
     os.Exit(1)
  }

  return os.Args[1], os.Args[2], os.Args[3]
}

// Create a TLS listener and echo back data received by clients.
func main() {
   certFilename, privKeyFilename, hostString := checkArgs()

   // Load the certificate and private key
   serverCert, err := tls.LoadX509KeyPair(certFilename, privKeyFilename)
   if err != nil {
      log.Fatal("Error loading certificate and private key. ", err)
   }

   // Set up certificates, host/ip, and port
   config := &tls.Config{
      // Specify server certificate
      Certificates: []tls.Certificate{serverCert},

      // By default no client certificate is required.
      // To require and validate client certificates, specify the
      // ClientAuthType to be one of:
      //    NoClientCert, RequestClientCert, RequireAnyClientCert,
      //    VerifyClientCertIfGiven, RequireAndVerifyClientCert)

      // ClientAuth: tls.RequireAndVerifyClientCert

      // Define the list of certificates you will accept as
      // trusted certificate authorities with ClientCAs.

      // ClientCAs: *x509.CertPool
   }

   // Create the TLS socket listener
   listener, err := tls.Listen("tcp", hostString, config)
   if err != nil {
      log.Fatal("Error starting TLS listener. ", err)
   }
   defer listener.Close()

   // Listen forever for connections
   for {
      clientConnection, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting client connection. ", err)
         continue
      }
      // Launch a goroutine(thread)go-1.6 to handle each connection
      go handleConnection(clientConnection)
   }
}

// Function that gets launched in a goroutine to handle client connection
func handleConnection(clientConnection net.Conn) {
   defer clientConnection.Close()
   socketReader := bufio.NewReader(clientConnection)
   for {
      // Read a message from the client
      message, err := socketReader.ReadString('\n')
      if err != nil {
         log.Println("Error reading from client socket. ", err)
         return
      }
      fmt.Println(message)

      // Echo back the data to the client.
      numBytesWritten, err := clientConnection.Write([]byte(message))
      if err != nil {
         log.Println("Error writing data to client socket. ", err)
         return
      }
      fmt.Printf("Wrote %d bytes back to client.\n", numBytesWritten)
   }
}
```

# TLS 客户端

TCP 套接字是在网络上进行通信的一种简单而常见的方式。在标准库中使用 Go 的 TLS 层覆盖标准 TCP 套接字非常简单。

客户端拨号 TLS 服务器就像标准套接字一样。客户端通常不需要任何类型的密钥或证书，但服务器可以实现客户端身份验证，并只允许特定用户连接。

该程序将连接到一个 TLS 服务器，并将 STDIN 的内容发送到远程服务器并读取响应。我们可以使用这个程序来测试在上一节中创建的基本 TLS 回显服务器。

在运行此程序之前，请确保上一节中的 TLS 服务器正在运行，以便您可以连接。

请注意，这是一个原始的套接字级服务器。它不是一个 HTTP 服务器。在第九章 *Web 应用*中，有一些运行 HTTPS TLS Web 服务器的示例。

默认情况下，客户端会验证服务器的证书是否由受信任的机构签名。我们必须覆盖这个默认设置，并告诉客户端不要验证证书，因为我们自己签名了它。受信任的证书颁发机构列表是从系统中加载的，但可以通过在`tls.Config`中填充 RootCAs 变量来覆盖。这个例子不会验证服务器证书，但提供了提供一组受信任的 RootCAs 的代码，供参考时注释掉。

您可以通过查看[`golang.org/src/crypto/x509/`](https://golang.org/src/crypto/x509/)中的`root_*.go`文件来了解 Go 如何为每个系统加载证书池。例如，`root_windows.go`和`root_linux.go`加载系统的默认证书。

如果您想连接到服务器并检查或存储其证书，您可以连接，然后检查客户端的`net.Conn.ConnectionState().PeerCertificates`。它以标准的`x509.Certificate`结构形式呈现。要这样做，请参考以下代码块：

```go
package main

import (
   "crypto/tls"
   "fmt"
   "log"
   "os"
)

func printUsage() {
   fmt.Println(os.Args[0] + ` - Send and receive a message to a TLS server

Usage:
  ` + os.Args[0] + ` <hostString>

Example:
  ` + os.Args[0] + ` localhost:9999
`)
}

func checkArgs() string {
   if len(os.Args) != 2 {
      printUsage()
      os.Exit(1)
   }

   // Host string e.g. localhost:9999
   return os.Args[1]
}

// Simple TLS client that sends a message and receives a message
func main() {
   hostString := checkArgs()
   messageToSend := "Hello?\n"

   // Configure TLS settings
   tlsConfig := &tls.Config{
      // Required to accept self-signed certs
      InsecureSkipVerify: true, 
      // Provide your client certificate if necessary
      // Certificates: []Certificate

      // ServerName is used to verify the hostname (unless you are     
      // skipping verification)
      // It is also included in the handshake in case the server uses   
      // virtual hosts Can also just be an IP address 
      // instead of a hostname.
      // ServerName: string,

      // RootCAs that you are willing to accept
      // If RootCAs is nil, the host's default root CAs are used
      // RootCAs: *x509.CertPool
   }

   // Set up dialer and call the server
   connection, err := tls.Dial("tcp", hostString, tlsConfig)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }
   defer connection.Close()

   // Write data to socket
   numBytesWritten, err := connection.Write([]byte(messageToSend))
   if err != nil {
      log.Println("Error writing to socket. ", err)
      os.Exit(1)
   }
   fmt.Printf("Wrote %d bytes to the socket.\n", numBytesWritten)

   // Read data from socket and print to STDOUT
   buffer := make([]byte, 100)
   numBytesRead, err := connection.Read(buffer)
   if err != nil {
      log.Println("Error reading from socket. ", err)
      os.Exit(1)
   }
   fmt.Printf("Read %d bytes to the socket.\n", numBytesRead)
   fmt.Printf("Message received:\n%s\n", buffer)
}
```

# 其他加密包

以下部分没有源代码示例，但值得一提。这些由 Go 提供的包是建立在前面示例中演示的原则之上的。

# OpenPGP

PGP 代表**相当好的隐私**，而 OpenPGP 是标准 RFC 4880。PGP 是一个方便的套件，用于加密文本、文件、目录和磁盘。所有原则都与前一节中讨论的 SSL 和 TLS 密钥/证书相同。加密、签名和验证都是一样的。Go 提供了一个 OpenPGP 包。在[`godoc.org/golang.org/x/crypto/openpgp`](https://godoc.org/golang.org/x/crypto/openpgp)上阅读更多关于它的信息。

# 离线记录（OTR）消息

**离线记录**或**OTR**消息是一种端到端加密，用户可以加密他们在任何消息媒介上的通信。这很方便，因为你可以在任何协议上实现加密层，即使协议本身是未加密的。例如，OTR 消息可以在 XMPP、IRC 和许多其他聊天协议上运行。许多聊天客户端，如 Pidgin、Adium 和 Xabber，都支持 OTR，无论是本地支持还是通过插件支持。Go 提供了一个用于实现 OTR 消息的包。在[`godoc.org/golang.org/x/crypto/otr/`](https://godoc.org/golang.org/x/crypto/otr/)上阅读更多关于 Go 的 OTR 支持的信息。

# 总结

阅读完本章后，您应该对 Go 密码包的功能有很好的理解。使用本章中提供的示例作为参考，您应该能够轻松地执行基本的哈希操作、加密、解密、生成密钥和使用密钥。

此外，您应该了解对称加密和非对称加密之间的区别，以及它与哈希的不同之处。您应该对运行 TLS 服务器和与 TLS 客户端连接的基础有所了解。

请记住，目标不是记住每一个细节，而是记住有哪些选项可供选择，以便您可以选择最适合工作的工具。

在下一章中，我们将讨论使用安全外壳（也称为 SSH）。首先介绍了使用公钥和私钥对以及密码进行身份验证，以及如何验证远程主机的密钥。我们还将介绍如何在远程服务器上执行命令以及如何创建交互式外壳。安全外壳利用了本章讨论的加密技术。这是加密的最常见和实用的应用之一。继续阅读，了解更多关于在 Go 中使用 SSH 的内容。
