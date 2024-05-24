# Go 标准库秘籍（三）

> 原文：[`zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406`](https://zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：发现文件系统

本章包含以下示例：

+   获取文件信息

+   创建临时文件

+   写入文件

+   从多个 goroutine 写入文件

+   列出目录

+   更改文件权限

+   创建文件和目录

+   过滤文件列表

+   比较两个文件

+   解析用户主目录

# 介绍

本章将引导您完成文件和目录中的典型操作。我们还将介绍如何获取用户主目录并为其创建临时文件。

检查 Go 是否已正确安装。第一章的*准备就绪*部分中的*检索 Golang 版本*示例将对您有所帮助。

# 获取文件信息

如果您需要发现有关访问文件的基本信息，Go 的标准库提供了一种方法来完成这个任务。本示例展示了如何访问这些信息。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe01`。

1.  导航到目录。

1.  创建包含内容`This is test file`的示例`test.file`。

1.  创建包含以下内容的`fileinfo.go`文件：

```go
        package main

        import (
          "fmt"
          "os"
        )

        func main() {

          f, err := os.Open("test.file")
          if err != nil {
            panic(err)
          }
          fi, err := f.Stat()
          if err != nil {
            panic(err)
          }

          fmt.Printf("File name: %v\n", fi.Name())
          fmt.Printf("Is Directory: %t\n", fi.IsDir())
          fmt.Printf("Size: %d\n", fi.Size())
          fmt.Printf("Mode: %v\n", fi.Mode())

        }
```

1.  在主终端中运行`go run fileinfo.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/e2f33ff9-7999-4025-b4ff-7e7e16fb7461.png)

# 它是如何工作的...

`os.File`类型通过`Stat`方法提供对`FileInfo`类型的访问。`FileInfo`结构包含有关文件的所有基本信息。

# 创建临时文件

临时文件通常在运行测试用例时使用，或者如果您的应用程序需要一个存储短期内容的地方，例如用户数据上传和当前处理的数据。本示例将介绍创建此类文件或目录的最简单方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe02`。

1.  导航到目录。

1.  创建包含以下内容的`tempfile.go`文件：

```go
        package main

        import "io/ioutil"
        import "os"
        import "fmt"

        func main() {
          tFile, err := ioutil.TempFile("", "gostdcookbook")
          if err != nil {
            panic(err)
          }
          // The called is responsible for handling
          // the clean up.
          defer os.Remove(tFile.Name())

          fmt.Println(tFile.Name())

          // TempDir returns
          // the path in string.
          tDir, err := ioutil.TempDir("", "gostdcookbookdir")
          if err != nil {
            panic(err)
          }
          defer os.Remove(tDir)
          fmt.Println(tDir)

        }
```

1.  在主终端中运行`go run tempfile.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/8eff29ed-d69c-4413-bb1d-72031e8dfdbe.png)

# 它是如何工作的...

`ioutil`包含`TempFile`和`TempDir`函数。`TempFile`函数消耗目录和文件前缀。返回具有底层临时文件的`os.File`。请注意，调用者负责清理文件。前面的示例使用`os.Remove`函数来清理文件。

`TempDir`函数的工作方式相同。不同之处在于返回包含目录路径的`string`。

临时`file`/`dir`名称由前缀和随机后缀组成。多个调用具有相同参数的`TempFile`/`Dir`函数的程序将不会获得相同的结果。

# 写入文件

写入文件是每个程序员的基本任务；Go 支持多种方法来完成这个任务。本示例将展示其中一些方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe03`。

1.  导航到目录。

1.  创建包含以下内容的`writefile.go`文件：

```go
        package main

        import (
          "io"
          "os"
          "strings"
        )

        func main() {

          f, err := os.Create("sample.file")
          if err != nil {
            panic(err)
          }
          defer f.Close()

          _, err = f.WriteString("Go is awesome!\n")
          if err != nil {
            panic(err)
          }

          _, err = io.Copy(f, strings.NewReader("Yeah! Go 
                           is great.\n"))
          if err != nil {
            panic(err)
          }
        }
```

1.  在主终端中运行`go run writefile.go`来执行代码。

1.  检查创建的`sample.file`的内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/11071c1b-0250-44c7-851b-aa46aee6bd05.png)

# 它是如何工作的...

`os.File`类型实现了`Writer`接口，因此可以通过使用`Writer`接口的任何选项来写入文件。前面的示例使用了`os.File`类型的`WriteString`方法。通用的`io.WriteString`方法也可以使用。

# 从多个 goroutine 写入文件

本示例将向您展示如何安全地从多个 goroutine 写入文件。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe04`。

1.  导航到目录。

1.  创建包含以下内容的`syncwrite.go`文件：

```go
        package main

        import (
          "fmt"
          "io"
          "os"
          "sync"
        )

        type SyncWriter struct {
          m sync.Mutex
          Writer io.Writer
        }

        func (w *SyncWriter) Write(b []byte) (n int, err error) {
          w.m.Lock()
          defer w.m.Unlock()
          return w.Writer.Write(b)
        }

        var data = []string{
          "Hello!",
          "Ola!",
          "Ahoj!",
        }

        func main() {

          f, err := os.Create("sample.file")
          if err != nil {
            panic(err)
          }

          wr := &SyncWriter{sync.Mutex{}, f}
          wg := sync.WaitGroup{}
          for _, val := range data {
            wg.Add(1)
            go func(greetings string) {
              fmt.Fprintln(wr, greetings)
              wg.Done()
            }(val)
          }

          wg.Wait()
        }
```

1.  在主终端中运行`go run syncwrite.go`来执行代码。

1.  检查创建的`sample.file`的内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/bfd4b0c5-3ce0-402a-b5f9-344d12d0f2da.png)

# 它是如何工作的...

并发写入文件是一个可能导致文件内容不一致的问题。最好通过使用`Mutex`或任何其他同步原语来同步对文件的写入。这样，您可以确保一次只有一个 goroutine 能够写入文件。

上述代码创建了一个带有`Mutex`的`Writer`，它嵌入了`Writer`（在本例中是`os.File`），对于每个`Write`调用，内部锁定`Mutex`以提供排他性。写操作完成后，`Mutex`原语会自然解锁。

# 列出目录

这个示例将向您展示如何列出目录内容。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe05`。

1.  导航到目录。

1.  创建一个名为`folder`的目录。

1.  创建`listdir.go`文件，并包含以下内容：

```go
        package main

        import (
          "fmt"
          "io/ioutil"
          "os"
          "path/filepath"
        )

        func main() {

          fmt.Println("List by ReadDir")
          listDirByReadDir(".")
          fmt.Println()
          fmt.Println("List by Walk")
          listDirByWalk(".")
        }

        func listDirByWalk(path string) {
          filepath.Walk(path, func(wPath string, info os.FileInfo,
                                   err error) error {

          // Walk the given dir
          // without printing out.
          if wPath == path {
            return nil
          }

          // If given path is folder
          // stop list recursively and print as folder.
          if info.IsDir() {
            fmt.Printf("[%s]\n", wPath)
            return filepath.SkipDir
          }

          // Print file name
          if wPath != path {
            fmt.Println(wPath)
          }
          return nil
        })
        }

        func listDirByReadDir(path string) {
          lst, err := ioutil.ReadDir(path)
          if err != nil {
            panic(err)
          }
          for _, val := range lst {
            if val.IsDir() {
              fmt.Printf("[%s]\n", val.Name())
            } else {
              fmt.Println(val.Name())
            }
          }
        }
```

1.  在主终端中运行`go run listdir.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/44fd0deb-bd33-4068-a8d7-25f36bf535db.png)

# 它是如何工作的...

上面的示例中的文件夹列表使用了两种方法。第一种更简单的方法是使用`listDirByReadDir`函数，并利用`ioutil`包中的`ReadDir`函数。此函数返回表示实际目录内容的`FileInfo`结构的切片。请注意，`ReadDir`函数不会递归读取文件夹。实际上，`ReadDir`函数在内部使用`os`包中`File`类型的`Readdir`方法。 

另一方面，更复杂的`listDirByWalk`使用`filepath.Walk`函数，该函数消耗要遍历的路径，并具有处理给定路径中的每个文件或文件夹的函数。主要区别在于`Walk`函数递归读取目录。这种方法的核心部分是`WalkFunc`类型，其函数是消耗列表的结果。请注意，该函数通过返回`filepath.SkipDir`错误来阻止基础文件夹上的递归调用。`Walk`函数还首先处理调用路径，因此您也需要处理这一点（在本例中，我们跳过打印并返回 nil，因为我们需要递归处理此文件夹）。

# 更改文件权限

这个示例说明了如何以编程方式更改文件权限。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe06`。

1.  导航到目录。

1.  创建`filechmod.go`文件，并包含以下内容：

```go
        package main

        import (
          "fmt"
          "os"
        )

        func main() {

          f, err := os.Create("test.file")
          if err != nil {
            panic(err)
          }
          defer f.Close()

          // Obtain current permissions
          fi, err := f.Stat()
          if err != nil {
            panic(err)
          }
          fmt.Printf("File permissions %v\n", fi.Mode())

          // Change permissions
          err = f.Chmod(0777)
          if err != nil {
            panic(err)
          }
          fi, err = f.Stat()
          if err != nil {
            panic(err)
          }
          fmt.Printf("File permissions %v\n", fi.Mode())

        }
```

1.  在主终端中运行`go run filechmod.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/43fb2a64-e3e7-46c8-80c1-c2cc04adb430.png)

# 它是如何工作的...

`os`包中`File`类型的`Chmod`方法可用于更改文件权限。上面的示例只是创建文件并将权限更改为`0777`。

只需注意`fi.Mode()`被调用两次，因为它提取了文件当前状态的权限（`os.FileMode`）。

更改权限的最简单方法是使用`os.Chmod`函数，它执行相同的操作，但您不需要在代码中获取`File`类型。

# 创建文件和目录

这个示例描述了在代码中创建文件和目录的几种一般方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe07`。

1.  导航到目录。

1.  创建`create.go`文件，并包含以下内容：

```go
        package main

        import (
          "os"
        )

        func main() {

          f, err := os.Create("created.file")
          if err != nil {
            panic(err)
          }
          f.Close()

          f, err = os.OpenFile("created.byopen", os.O_CREATE|os.O_APPEND,
                               os.ModePerm)
          if err != nil {
            panic(err)
          }
          f.Close()

          err = os.Mkdir("createdDir", 0777)
          if err != nil {
            panic(err)
          }

          err = os.MkdirAll("sampleDir/path1/path2", 0777)
          if err != nil {
            panic(err)
          }

        }
```

1.  在主终端中运行`go run create.go`来执行代码。

1.  列出`chapter06/recipe07`目录的内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/f3fed783-e2ae-485f-8dac-2d249b399835.png)

# 它是如何工作的...

前面的示例代表了创建文件或目录的四种方法。`os.Create`函数是创建文件的最简单方法。使用此函数，您将以`0666`的权限创建文件。

如果需要使用任何其他权限配置创建文件，则应使用`os`包的`OpenFile`函数。

可以使用`os`包的`Mkdir`函数创建目录。这样，将创建具有给定权限的目录。第二个选项是使用`MkdirAll`函数。此函数还会创建目录，但如果给定路径包含不存在的目录，则会创建路径中的所有目录（它与 Unix 的`mkdir`实用程序的`-p`选项的工作方式相同）。

# 过滤文件列表

本教程向您展示了如何列出与给定模式匹配的文件路径。列表不必来自同一文件夹。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe08`。

1.  导航到目录。

1.  创建`filter.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os"
          "path/filepath"
        )

        func main() {

          for i := 1; i <= 6; i++ {
            _, err := os.Create(fmt.Sprintf("./test.file%d", i))
            if err != nil {
              fmt.Println(err)
            }
          }

          m, err := filepath.Glob("./test.file[1-3]")
          if err != nil {
            panic(err)
          }

          for _, val := range m {
            fmt.Println(val)
          }

          // Cleanup
          for i := 1; i <= 6; i++ {
            err := os.Remove(fmt.Sprintf("./test.file%d", i))
            if err != nil {
              fmt.Println(err)
            }
          }
        }
```

1.  在主终端中运行`go run filter.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/7f64fba3-2f97-4423-971d-910b0c7a38a8.png)

# 它是如何工作的...

要获取与给定模式对应的过滤文件列表，可以使用`filepath`包中的`Glob`函数。有关模式语法，请参阅`filepath.Match`函数的文档（[`golang.org/pkg/path/filepath/#Match`](https://golang.org/pkg/path/filepath/#Match)）。

请注意，`filepath.Glob`的返回结果是与匹配路径对应的字符串切片。

# 另请参阅

本章的*列出目录*教程展示了更通用的方法，其中可以使用`filepath.Walk`函数来列出和过滤路径。

# 比较两个文件

本教程为您提供了如何比较两个文件的提示。本教程将向您展示如何快速确定文件是否相同。本教程还将向您展示如何找到两者之间的差异。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe09`。

1.  导航到目录。

1.  创建`comparison.go`文件，内容如下：

```go
        package main

        import (
          "bufio"
          "crypto/md5"
          "fmt"
          "io"
          "os"
        )

        var data = []struct {
          name string
          cont string
          perm os.FileMode
        }{
          {"test1.file", "Hello\nGolang is great", 0666},
          {"test2.file", "Hello\nGolang is great", 0666},
          {"test3.file", "Not matching\nGolang is great\nLast line",
           0666},
        }

        func main() {

          files := []*os.File{}
          for _, fData := range data {
            f, err := os.Create(fData.name)
            if err != nil {
              panic(err)
            }
            defer f.Close()
            _, err = io.WriteString(f, fData.cont)
            if err != nil {
              panic(err)
            }
            files = append(files, f)
          }

          // Compare by checksum
          checksums := []string{}
          for _, f := range files {
            f.Seek(0, 0) // reset to beginning of file
            sum, err := getMD5SumString(f)
            if err != nil {
              panic(err)
            }
            checksums = append(checksums, sum)
          }

          fmt.Println("### Comparing by checksum ###")
          compareCheckSum(checksums[0], checksums[1])
          compareCheckSum(checksums[0], checksums[2])

          fmt.Println("### Comparing line by line ###")
          files[0].Seek(0, 0)
          files[2].Seek(0, 0)
          compareFileByLine(files[0], files[2])

          // Cleanup
          for _, val := range data {
            os.Remove(val.name)
          }

        }

        func getMD5SumString(f *os.File) (string, error) {
          file1Sum := md5.New()
          _, err := io.Copy(file1Sum, f)
          if err != nil {
            return "", err
          }
          return fmt.Sprintf("%X", file1Sum.Sum(nil)), nil
        }

        func compareCheckSum(sum1, sum2 string) {
          match := "match"
          if sum1 != sum2 {
            match = " does not match"
          }
          fmt.Printf("Sum: %s and Sum: %s %s\n", sum1, sum2, match)
        }

        func compareLines(line1, line2 string) {
          sign := "o"
          if line1 != line2 {
            sign = "x"
          }
          fmt.Printf("%s | %s | %s \n", sign, line1, line2)
        }

        func compareFileByLine(f1, f2 *os.File) {
          sc1 := bufio.NewScanner(f1)
          sc2 := bufio.NewScanner(f2)

          for {
            sc1Bool := sc1.Scan()
            sc2Bool := sc2.Scan()
            if !sc1Bool && !sc2Bool {
              break
            }
            compareLines(sc1.Text(), sc2.Text())
          }
        }
```

1.  在主终端中运行`go run comparison.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/5a8c71ae-bf9f-4fb3-b6f2-8199b1e68b4b.png)

# 它是如何工作的...

可以通过几种方式来比较两个文件。本教程描述了两种基本方法。第一种方法是通过创建文件的校验和来比较整个文件。

第三章的*生成校验和*教程展示了如何创建文件的校验和。这种方式，`getMD5SumString`函数生成校验和字符串，它是 MD5 字节结果的十六进制表示。然后比较这些字符串。

第二种方法是逐行比较文件（在本例中是字符串内容）。如果行不匹配，则包括`x`标记。这是您可以比较二进制内容的方式，但您需要按字节块（字节切片）扫描文件。

# 解析用户主目录

例如，程序知道用户的主目录可能是有益的，例如，如果您需要存储自定义用户配置或与用户相关的任何其他数据。本教程将描述如何找到当前用户的主目录。

# 如何做...

1.  打开控制台并创建文件夹`chapter06/recipe10`。

1.  导航到目录。

1.  创建`home.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "log"
          "os/user"
        )

        func main() {
          usr, err := user.Current()
          if err != nil {
            log.Fatal(err)
          }
          fmt.Println("The user home directory: " + usr.HomeDir)
        }
```

1.  在主终端中运行`go run home.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/b2bf798b-0699-4ddc-84da-74155349b6b1.png)

# 它是如何工作的...

`os/user`包包含`Current`函数，它提供`os.User`类型的指针。`User`包含`HomeDir`属性，其中包含当前用户主目录的路径。

请注意，这对于交叉编译的代码不起作用，因为实现取决于本机代码。


# 第七章：连接网络

本章包含以下示例：

+   解析本地 IP 地址

+   连接到远程服务器

+   通过 IP 地址解析域名，反之亦然

+   连接到 HTTP 服务器

+   解析和构建 URL

+   创建 HTTP 请求

+   读取和写入 HTTP 头

+   处理 HTTP 重定向

+   使用 RESTful API

+   发送简单的电子邮件

+   调用 JSON-RPC 服务

# 介绍

本章主要讨论网络。本章中的大多数示例都集中在客户端。我们将介绍如何解析有关机器、域名和 IP 解析的基本信息，以及如何通过 TCP 相关协议（如 HTTP 和 SMTP）进行连接。最后，我们将使用标准库进行 JSON-RCP 1.0 的远程过程调用。

检查 Go 是否已正确安装。第一章中的*准备就绪*部分中的*检索 Golang 版本*示例，*与环境交互*，将有所帮助。验证是否有其他应用程序阻止了`7070`端口。

# 解析本地 IP 地址

本示例解释了如何从可用的本地接口中检索 IP 地址。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe01`。

1.  导航到目录。

1.  创建`interfaces.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "net"
        )

        func main() {

          // Get all network interfaces
          interfaces, err := net.Interfaces()
          if err != nil {
            panic(err)
          }

          for _, interf := range interfaces {
            // Resolve addresses
            // for each interface
            addrs, err := interf.Addrs()
            if err != nil {
              panic(err)
            }
            fmt.Println(interf.Name)
            for _, add := range addrs {
              if ip, ok := add.(*net.IPNet); ok {
                fmt.Printf("\t%v\n", ip)
              }
            }

          }
        }
```

1.  在主终端中运行`go run interfaces.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ddce79d8-a358-413f-8c89-f021731934eb.png)

# 它是如何工作的...

net 包包含`Interfaces`函数，它将网络接口列为`Interface`结构的切片。`Interface`结构具有`Addrs`方法，它列出可用的网络地址。这样，您可以按接口列出地址。

另一个选项是使用`net`包的`InterfaceAddrs`函数，它提供了实现`Addr`接口的结构体切片。这为您提供了获取所需信息的方法。

# 连接到远程服务器

基于 TCP 的协议是网络通信中最重要的协议。作为提醒，HTTP、FTP、SMTP 和其他协议都属于这一组。本示例让您了解如何一般连接到 TCP 服务器。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe02`。

1.  导航到目录。

1.  创建`tcpclient.go`文件，内容如下：

```go
        package main

        import (
          "bufio"
          "context"
          "fmt"
          "io"
          "net"
          "net/http"
          "time"
        )

        type StringServer string

        func (s StringServer) ServeHTTP(rw http.ResponseWriter,
                                        req *http.Request) {
          rw.Write([]byte(string(s)))
        }

        func createServer(addr string) http.Server {
          return http.Server{
            Addr: addr,
            Handler: StringServer("HELLO GOPHER!\n"),
          }
       }

       const addr = "localhost:7070"

       func main() {
         s := createServer(addr)
         go s.ListenAndServe()

         // Connect with plain TCP
         conn, err := net.Dial("tcp", addr)
         if err != nil {
           panic(err)
         }
         defer conn.Close()

         _, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost:
                                 localhost:7070\r\n\r\n")
         if err != nil {
           panic(err)
         }

         scanner := bufio.NewScanner(conn)
         conn.SetReadDeadline(time.Now().Add(time.Second))
         for scanner.Scan() {
           fmt.Println(scanner.Text())
         }

         ctx, _ := context.WithTimeout(context.Background(),
                                       5*time.Second)
         s.Shutdown(ctx)

       }
```

1.  在主终端中运行`go run tcpclient.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/bccd624a-a108-4726-9e67-e477ed5af73a.png)

# 它是如何工作的...

net 包包含`Dial`函数，它消耗网络类型和地址。在前面的示例中，网络是`tcp`，地址是`localhost:8080`。

一旦`Dial`函数成功，就会返回`Conn`类型，它作为已打开套接字的引用。`Conn`接口还定义了`Read`和`Write`函数，因此它们可以用作写入和从套接字读取的`Writer`和`Reader`函数。最后，示例代码使用`Scanner`来获取响应。请注意，这种情况下`Scanner`可以工作是因为有换行符。否则，应该使用更通用的`Read`方法。在示例中，通过`SetReadDeadline`方法设置了`Read`截止日期。关键之处在于截止日期不是持续时间，而是`Time`。这意味着截止日期被设置为将来的时间点。如果您在循环中从套接字读取数据并需要将读取超时设置为 10 秒，则每次迭代都应包含类似于`conn.SetReadDeadline(time.Now().Add(10*time.Second))`的代码。

只是为了解释整个代码示例，使用了`HTTP`标准包中的 HTTP 服务器作为客户端的对应部分。这部分在另一个示例中有所涵盖。

# 通过 IP 地址解析域名，反之亦然

这个教程将介绍如何将 IP 地址转换为主机地址，反之亦然。

# 如何做到...

1.  打开控制台并创建文件夹`chapter07/recipe03`。

1.  导航到目录。

1.  创建`lookup.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "net"
        )

        func main() {

          // Resolve by IP
          addrs, err := net.LookupAddr("127.0.0.1")
          if err != nil {
            panic(err)
          }

          for _, addr := range addrs {
            fmt.Println(addr)
          }

          //Resolve by address
          ips, err := net.LookupIP("localhost")
          if err != nil {
            panic(err)
          }

          for _, ip := range ips {
            fmt.Println(ip.String())
          }
        }
```

1.  在主终端中运行`go run lookup.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/5e731d6f-2943-4a89-9c3c-b4758c812f9d.png)

# 它是如何工作的...

从 IP 地址解析域名可以使用`net`包中的`LookupAddr`函数来完成。要从域名找出 IP 地址，应用`LookupIP`函数。

# 连接到 HTTP 服务器

前面的教程*连接到远程服务器*让我们深入了解了如何在较低级别连接 TCP 服务器。在这个教程中，将展示如何在较高级别与 HTTP 服务器通信。

# 如何做到...

1.  打开控制台并创建文件夹`chapter07/recipe04`。

1.  导航到目录。

1.  创建`http.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "io/ioutil"
          "net/http"
          "net/url"
          "strings"
        )

        type StringServer string

        func (s StringServer) ServeHTTP(rw http.ResponseWriter,
                                        req *http.Request) {
          req.ParseForm()
          fmt.Printf("Received form data: %v\n", req.Form)
          rw.Write([]byte(string(s)))
        } 

        func createServer(addr string) http.Server {
          return http.Server{
            Addr: addr,
            Handler: StringServer("Hello world"),
          }
        }

        const addr = "localhost:7070"

        func main() {
          s := createServer(addr)
          go s.ListenAndServe()

          useRequest()
          simplePost()

        }

        func simplePost() {
          res, err := http.Post("http://localhost:7070",
                          "application/x-www-form-urlencoded",
                          strings.NewReader("name=Radek&surname=Sohlich"))
          if err != nil {
            panic(err)
          }

          data, err := ioutil.ReadAll(res.Body)
          if err != nil {
            panic(err)
          }
          res.Body.Close()
          fmt.Println("Response from server:" + string(data))
        }

        func useRequest() {

          hc := http.Client{}
          form := url.Values{}
          form.Add("name", "Radek")
          form.Add("surname", "Sohlich")

          req, err := http.NewRequest("POST",
                        "http://localhost:7070",
                        strings.NewReader(form.Encode()))
                        req.Header.Add("Content-Type",
                        "application/x-www-form-urlencoded")

          res, err := hc.Do(req)

          if err != nil {
            panic(err)
          }

          data, err := ioutil.ReadAll(res.Body)
          if err != nil {
            panic(err)
          }
          res.Body.Close()
          fmt.Println("Response from server:" + string(data))
        }
```

1.  在主终端中运行`go run http.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/5b70d6e0-fa81-4aa0-ab14-68185d52291e.png)

# 它是如何工作的...

连接到 HTTP 服务器可以借助`net/http`包来完成。当然，你还有其他方法可以实现这一点，但上面的代码说明了两种最常见的方法。第一种选项实现了`simplePost`函数，并且演示了使用默认客户端。这里选择了 POST 方法，因为它比 GET 更复杂。`Post`方法接受 URL、内容类型和`Reader`形式的主体。调用`Post`函数立即请求服务器并返回结果。

请注意，`Post`方法只是在其实现中使用了`http.DefaultClient`的一个包装函数。`net/http`包还包含`Get`函数。

`useRequest`函数实现了相同的功能，但使用了更可定制的 API 和自己的`Client`实例。该实现利用`NewRequest`函数根据给定的参数创建请求：方法、URL 和请求主体。内容类型必须单独设置到`Header`属性中。请求是通过`Client`上创建的`Do`方法执行的。

# 另请参阅

*创建一个 HTTP 请求*的教程将帮助您详细组装请求。

# 解析和构建 URL

在许多情况下，最好使用方便的工具来操作 URL，而不是试图将其作为简单的字符串处理。Go 标准库自然包含了操作 URL 的工具。这个教程将介绍其中一些主要功能。

# 如何做到...

1.  打开控制台并创建文件夹`chapter07/recipe05`。

1.  导航到目录。

1.  创建`url.go`文件，内容如下：

```go
        package main

        import (
          "encoding/json"
          "fmt"
          "net/url"
        )

        func main() {

          u := &url.URL{}
          u.Scheme = "http"
          u.Host = "localhost"
          u.Path = "index.html"
          u.RawQuery = "id=1&name=John"
          u.User = url.UserPassword("admin", "1234")

          fmt.Printf("Assembled URL:\n%v\n\n\n", u)

          parsedURL, err := url.Parse(u.String())
          if err != nil {
            panic(err)
          }
          jsonURL, err := json.Marshal(parsedURL)
          if err != nil {
            panic(err)
          }
          fmt.Println("Parsed URL:")
          fmt.Println(string(jsonURL))

        }
```

1.  在主终端中运行`go run url.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c373cc32-7a41-4cad-b4e1-f4f39a2f4d57.png)

# 它是如何工作的...

`net/url`包旨在帮助您操作和解析 URL。`URL`结构包含了组合 URL 所需的字段。通过`URL`结构的`String`方法，可以轻松地将其转换为简单的字符串。

当字符串表示可用且需要额外操作时，可以利用`net/url`的`Parse`函数。这样，字符串可以转换为`URL`结构，并且可以修改底层 URL。

# 创建一个 HTTP 请求

这个教程将向您展示如何使用特定参数构造 HTTP 请求。

# 如何做到...

1.  打开控制台并创建文件夹`chapter07/recipe06`。

1.  导航到目录。

1.  创建`request.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "io/ioutil"
          "net/http"
          "net/url"
          "strings"
        )

        type StringServer string

        func (s StringServer) ServeHTTP(rw http.ResponseWriter,
                                        req *http.Request) {
          req.ParseForm()
          fmt.Printf("Received form data: %v\n", req.Form)
          fmt.Printf("Received header: %v\n", req.Header)
          rw.Write([]byte(string(s)))
        }

        func createServer(addr string) http.Server {
          return http.Server{
            Addr: addr,
            Handler: StringServer("Hello world"),
          }
        } 

        const addr = "localhost:7070"

        func main() {
          s := createServer(addr)
          go s.ListenAndServe()

          form := url.Values{}
          form.Set("id", "5")
          form.Set("name", "Wolfgang")

          req, err := http.NewRequest(http.MethodPost,
                              "http://localhost:7070",
                              strings.NewReader(form.Encode()))

          if err != nil {
            panic(err)
          }
          req.Header.Set("Content-Type",
                         "application/x-www-form-urlencoded")

          res, err := http.DefaultClient.Do(req)
          if err != nil {
            panic(err)
          }
          data, err := ioutil.ReadAll(res.Body)
          if err != nil {
            panic(err)
          }
          res.Body.Close()
          fmt.Println("Response from server:" + string(data))

        }
```

1.  在主终端中运行`go run request.go`来执行代码。

1.  你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/1dd93ab3-741d-4210-9731-15401233a43c.png)

# 它是如何工作的...

构造请求的更复杂的方式在示例代码中呈现。使用`net/http`包的`NewRequest`方法返回`Request`结构的指针。该函数消耗方法的请求、URL 和请求的主体。注意表单的构建方式。使用`url.Values`结构而不是使用普通字符串。最后，调用`Encode`方法对给定的表单值进行编码。通过请求的`http.Header`属性设置头。

# 读取和写入 HTTP 头

前面的示例描述了如何一般创建 HTTP 请求。本示例将详细介绍如何读取和写入请求头。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe07`。

1.  导航到目录。

1.  创建包含以下内容的`headers.go`文件：

```go
        package main

        import (
          "fmt"
          "net/http"
        )

        func main() {

          header := http.Header{}

          // Using the header as slice
          header.Set("Auth-X", "abcdef1234")
          header.Add("Auth-X", "defghijkl")
          fmt.Println(header)

          // retrieving slice of values in header
          resSlice := header["Auth-X"]
          fmt.Println(resSlice)

          // get the first value
          resFirst := header.Get("Auth-X")
          fmt.Println(resFirst)

          // replace all existing values with
          // this one
          header.Set("Auth-X", "newvalue")
          fmt.Println(header)

          // Remove header
          header.Del("Auth-X")
          fmt.Println(header)

        }
```

1.  在主终端中运行`go run headers.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c967698b-5d62-4f82-bca4-24abeb3a84a2.png)

# 它是如何工作的...

`http`包中的头实际上表示为`map[string][]string`，因此必须处理`Header`类型。前面的代码显示了如何设置和读取头值。关于头的重要事情是头键的值是`string`切片。因此，头中的每个键可以包含多个值。

`Header`类型的`Set`方法设置给定键下的单项切片。另一方面，`Add`方法将值附加到切片。

使用`Get`方法将从给定键下的切片中检索第一个值。如果需要整个切片，则需要将`Header`处理为映射。可以使用`Del`方法删除整个头键。

服务器和客户端都使用`http`包的`Request`和`Header`类型，因此在服务器端和客户端端的处理方式相同。

# 处理 HTTP 重定向

在某些情况下，您需要更多控制重定向的处理方式。本示例将向您展示 Go 客户端实现的机制，以便您更多地控制处理 HTTP 重定向。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe08`。

1.  导航到目录。

1.  创建包含以下内容的`redirects.go`文件：

```go
        package main

        import (
          "fmt"
          "net/http"
        )

        const addr = "localhost:7070"

        type RedirecServer struct {
          redirectCount int
        }

        func (s *RedirecServer) ServeHTTP(rw http.ResponseWriter,
                                          req *http.Request) {
          s.redirectCount++
          fmt.Println("Received header: " + 
                      req.Header.Get("Known-redirects"))
          http.Redirect(rw, req, fmt.Sprintf("/redirect%d",
                        s.redirectCount), http.StatusTemporaryRedirect)
        }

        func main() {
          s := http.Server{
            Addr: addr,
            Handler: &RedirecServer{0},
          }
          go s.ListenAndServe()

          client := http.Client{}
          redirectCount := 0

          // If the count of redirects is reached
          // than return error.
          client.CheckRedirect = func(req *http.Request, 
                                 via []*http.Request) error {
            fmt.Println("Redirected")
            if redirectCount > 2 {
              return fmt.Errorf("Too many redirects")
            }
            req.Header.Set("Known-redirects", fmt.Sprintf("%d",
                           redirectCount))
            redirectCount++
            for _, prReq := range via {
              fmt.Printf("Previous request: %v\n", prReq.URL)
            }
            return nil
          }

          _, err := client.Get("http://" + addr)
          if err != nil {
            panic(err)
          }
        }
```

1.  在主终端中运行`go run redirects.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/16caaadf-4b4a-439c-bf90-621f97acd7af.png)

# 它是如何工作...

`http`包的`Client`包含`CheckRedirect`字段。该字段是一个具有`req`和`via`参数的函数。`req`是即将到来的请求，`via`指的是以前的请求。这样，您可以在重定向后修改请求。在前面的示例中，修改了`Known-redirects`头。

如果`CheckRedirect`函数返回错误，则返回带有包装错误的关闭主体的最后响应。如果返回`http.ErrUseLastResponse`，则返回最后的响应，但主体未关闭，因此可以读取它。

默认情况下，`CheckRedirect`属性为 nil。在这种情况下，它最多有 10 次重定向。超过此计数后，重定向将停止。

# 消费 RESTful API

RESTful API 是应用程序和服务器提供其服务访问的最常见方式。本示例将向您展示如何使用标准库中的 HTTP 客户端来消费它。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe09`。

1.  导航到目录。

1.  创建包含以下内容的`rest.go`文件：

```go
        package main

        import (
          "encoding/json"
          "fmt"
          "io"
          "io/ioutil"
          "net/http"
          "strconv"
          "strings"
        )

        const addr = "localhost:7070"

        type City struct {
          ID string
          Name string `json:"name"`
          Location string `json:"location"`
        }

        func (c City) toJson() string {
          return fmt.Sprintf(`{"name":"%s","location":"%s"}`,
                             c.Name, c.Location)
        }

        func main() {
          s := createServer(addr)
          go s.ListenAndServe()

          cities, err := getCities()
          if err != nil {
            panic(err)
          }
          fmt.Printf("Retrived cities: %v\n", cities)

          city, err := saveCity(City{"", "Paris", "France"})
          if err != nil {
            panic(err)
          }
          fmt.Printf("Saved city: %v\n", city)

        }

        func saveCity(city City) (City, error) {
          r, err := http.Post("http://"+addr+"/cities",
                              "application/json",
                               strings.NewReader(city.toJson()))
          if err != nil {
            return City{}, err
          }
          defer r.Body.Close()
          return decodeCity(r.Body)
        }

        func getCities() ([]City, error) {
          r, err := http.Get("http://" + addr + "/cities")
          if err != nil {
            return nil, err
          }
          defer r.Body.Close()
          return decodeCities(r.Body)
        }

        func decodeCity(r io.Reader) (City, error) {
          city := City{}
          dec := json.NewDecoder(r)
          err := dec.Decode(&city)
          return city, err
        }

       func decodeCities(r io.Reader) ([]City, error) {
         cities := []City{}
         dec := json.NewDecoder(r)
         err := dec.Decode(&cities)
         return cities, err
       }

       func createServer(addr string) http.Server {
         cities := []City{City{"1", "Prague", "Czechia"},
                          City{"2", "Bratislava", "Slovakia"}}
         mux := http.NewServeMux()
         mux.HandleFunc("/cities", func(w http.ResponseWriter,
                                        r *http.Request) {
           enc := json.NewEncoder(w)
           if r.Method == http.MethodGet {
             enc.Encode(cities)
           } else if r.Method == http.MethodPost {
             data, err := ioutil.ReadAll(r.Body)
             if err != nil {
               http.Error(w, err.Error(), 500)
             }
             r.Body.Close()
             city := City{}
             json.Unmarshal(data, &city)
             city.ID = strconv.Itoa(len(cities) + 1)
             cities = append(cities, city)
             enc.Encode(city)
           }

         })
         return http.Server{
           Addr: addr,
           Handler: mux,
         }
       }
```

1.  在主终端中运行`go run rest.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/026dbca2-62a0-4b65-8374-3237366a0446.png)

# 它是如何工作的...

前面的示例代码显示了 REST API 的样子以及如何使用它。请注意，`decodeCity`和`decodeCities`函数受益于请求的`Body`实现了`Reader`接口。结构的反序列化通过`json.Decoder`完成。

# 发送简单的电子邮件

本教程将简要介绍如何使用标准库连接到 SMTP 服务器并发送电子邮件。

# 准备工作

在本教程中，我们将使用谷歌 Gmail 账户发送电子邮件。通过一些配置，本教程也适用于其他 SMTP 服务器。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe10`。

1.  导航到目录。

1.  创建`smtp.go`文件，内容如下：

```go
        package main

        import (
          "crypto/tls"
          "fmt"
          "net/smtp"
        )

        func main() {

          var email string
          fmt.Println("Enter username for smtp: ")
          fmt.Scanln(&email)

          var pass string
          fmt.Println("Enter password for smtp: ")
          fmt.Scanln(&pass)

          auth := smtp.PlainAuth("", email, pass, "smtp.gmail.com")

          c, err := smtp.Dial("smtp.gmail.com:587")
          if err != nil {
            panic(err)
          }
          defer c.Close()
          config := &tls.Config{ServerName: "smtp.gmail.com"}

          if err = c.StartTLS(config); err != nil {
            panic(err)
          }

          if err = c.Auth(auth); err != nil {
            panic(err)
          }

          if err = c.Mail(email); err != nil {
            panic(err)
          }
          if err = c.Rcpt(email); err != nil {
            panic(err)
          }

          w, err := c.Data()
          if err != nil {
            panic(err)
          }

          msg := []byte("Hello this is content")
          if _, err := w.Write(msg); err != nil {
            panic(err)
          }

          err = w.Close()
          if err != nil {
            panic(err)
          }
          err = c.Quit()

          if err != nil {
            panic(err)
          }

        }
```

1.  在主终端中运行`go run smtp.go`来执行代码。

1.  输入账户的电子邮件（谷歌账户）并按*Enter*。

1.  输入账户的密码并按*Enter*。

1.  在检查电子邮箱之前，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/d25ce8a3-09ac-4b00-b46b-f4fbe10e3cbc.png)

# 工作原理...

`smtp`包提供了与 SMTP 服务器交互的基本功能。`Dial`函数提供客户端。客户端最重要的方法是`Mail`，用于设置发件人邮件，`Rcpt`，用于设置收件人邮件，以及`Data`，提供`Writer`，用于写入邮件内容。最后，`Quit`方法发送 QUIT 并关闭与服务器的连接。

前面的示例使用了安全连接到 SMTP 服务器，因此客户端的`Auth`方法用于设置身份验证，并调用`StartTLS`方法以启动与服务器的安全连接。

请注意，`Auth`结构是通过`smtp`包的`PlainAuth`函数单独创建的。

# 调用 JSON-RPC 服务

本教程将说明如何使用标准库调用 JSON-RPC 协议的过程。

# 如何做...

1.  打开控制台并创建文件夹`chapter07/recipe11`。

1.  导航到目录。

1.  创建`jsonrpc.go`文件，内容如下：

```go
        package main

        import (
          "log"
          "net"
          "net/rpc"
          "net/rpc/jsonrpc"
        )

        type Args struct {
          A, B int
        }

        type Result int

        type RpcServer struct{}

        func (t RpcServer) Add(args *Args, result *Result) error {
          log.Printf("Adding %d to %d\n", args.A, args.B)
          *result = Result(args.A + args.B)
          return nil
        } 

        const addr = ":7070"

        func main() {
          go createServer(addr)
          client, err := jsonrpc.Dial("tcp", addr)
          if err != nil {
            panic(err)
          }
          defer client.Close()
          args := &Args{
            A: 2,
            B: 3,
          }
          var result Result
          err = client.Call("RpcServer.Add", args, &result)
          if err != nil {
            log.Fatalf("error in RpcServer", err)
          }
          log.Printf("%d+%d=%d\n", args.A, args.B, result)
        }

        func createServer(addr string) {
          server := rpc.NewServer()
          err := server.Register(RpcServer{})
          if err != nil {
            panic(err)
          }
          l, e := net.Listen("tcp", addr)
          if e != nil {
            log.Fatalf("Couldn't start listening on %s errors: %s",
                       addr, e)
          }
          for {
            conn, err := l.Accept()
            if err != nil {
              log.Fatal(err)
            }
            go server.ServeCodec(jsonrpc.NewServerCodec(conn))
          }
        }
```

1.  在主终端中运行`go run jsonrpc.go`来执行代码。

1.  您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/b08751bc-986a-4834-a877-7b3691ec84ab.png)

# 工作原理...

Go 的标准库作为其内置包的一部分实现了 JSON-RPC 1.0。`jsonrpc`包实现了`Dial`函数，用于生成调用远程过程的客户端。客户端本身包含`Call`方法，接受过程调用、参数和结果存储的指针。

`createServer`将创建一个示例服务器来测试客户端调用。

HTTP 协议可以用作 JSON-RPC 的传输层。`net/rpc`包包含`DialHTTP`函数，能够创建客户端并调用远程过程。


# 第八章：使用数据库

本章包含以下配方：

+   连接数据库

+   验证连接

+   执行语句

+   使用预处理语句进行操作

+   取消挂起的查询

+   读取查询结果元数据

+   从查询结果中检索数据

+   将查询结果解析为映射

+   处理事务

+   执行存储过程和函数

# 介绍

每个数据库服务器都有自己的特点，而且协议也不同。自然地，语言库内部与数据库通信必须定制以适用于特定协议。

Go 标准库提供了用于与数据库服务器通信和操作的统一 API。此 API 位于`sql`包中。要使用特定的数据库服务器，必须导入驱动程序。此驱动程序需要符合`sql`包的规范。这样，您将能够受益于统一的方法。在本章中，我们将描述数据库操作的基础知识、事务处理以及如何使用存储过程。请注意，我们将在 PostgreSQL 数据库上说明该方法，但这些方法适用于大多数其他数据库。

# 连接数据库

与数据库工作的关键部分是与数据库本身的连接。Go 标准包仅涵盖了与数据库交互的抽象，必须使用第三方驱动程序。

在本配方中，我们将展示如何连接到 PostgreSQL 数据库。但是，这种方法适用于所有其他驱动程序实现了标准 API 的数据库。

# 准备就绪

通过在终端中调用`go version`命令验证 Go 是否已正确安装。如果命令失败，请执行以下操作：

+   通过`go get -u github.com/lib/pq`获取 PostgreSQL 驱动程序

+   安装 PostgreSQL 数据库服务器（可选择使用 Docker 镜像而不是安装到主机系统）

+   我们将使用默认用户`postgres`和密码`postgres`

+   创建名为`example`的数据库

# 如何做...

1.  打开控制台并创建文件夹`chapter08/recipe01`。

1.  导航到目录。

1.  使用以下内容创建`connect.go`文件：

```go
       package main

       import (
         "database/sql"
         "fmt"

         _ "github.com/lib/pq"
       )

       func main() {
         connStr := "postgres://postgres:postgres@
                     localhost:5432/example?sslmode=disable"
         db, err := sql.Open("postgres", connStr)
         if err != nil {
           panic(err)
         }
         defer db.Close()
         err = db.Ping()
         if err != nil {
           panic(err)
         }
         fmt.Println("Ping OK")
       }
```

1.  通过`go run connect.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/dc43c34f-78b8-4cd5-82e5-6541753840dc.png)

# 工作原理...

标准库包`database/sql`提供了`Open`函数，用于使用驱动程序名称和连接详细信息（在本例中为连接 URL）初始化与数据库的连接。请注意，`Open`函数不会立即创建连接，可能只会验证传递给函数的参数。

可以通过返回的`DB`结构指针中可用的`Ping`方法验证与数据库的连接。

驱动程序本身在`driver`包的`init`函数中初始化。驱动程序通过`sql`包的`Register`函数向驱动程序名称注册自身。`github.com/lib/pq`驱动程序将自身注册为`postgres`。

# 验证连接

驱动程序实现中的数据库连接可能被池化，并且可能从池中拉出的连接已经断开。本配方将展示如何验证连接是否仍然有效。

# 准备就绪

通过在终端中调用`go version`命令验证 Go 是否已正确安装。如果命令失败，请按照本章第一个配方中的*准备就绪*部分进行操作。

# 如何做...

1.  打开控制台并创建文件夹`chapter08/recipe02`。

1.  导航到目录。

1.  使用以下内容创建`verify.go`文件：

```go
        package main

        import (
          "context"
          "database/sql"
          "fmt"
          "time"

          _ "github.com/lib/pq"
        )

        func main() {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          defer db.Close()
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          fmt.Println("Ping OK.")
          ctx, _ := context.WithTimeout(context.Background(),
                                        time.Nanosecond)
          err = db.PingContext(ctx)
          if err != nil {
            fmt.Println("Error: " + err.Error())
          }

          // Verify the connection is
          conn, err := db.Conn(context.Background())
          if err != nil {
            panic(err)
          }
          defer conn.Close()
          err = conn.PingContext(context.Background())
          if err != nil {
            panic(err)
          }
          fmt.Println("Connection Ping OK.")

        }
```

1.  通过`go run verify.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9d5ba3af-08c2-4c54-93bd-25541dc94e8e.png)

# 工作原理...

如前一篇中提到的*连接数据库*，`Open`函数可能只是验证连接细节，但不一定立即连接数据库。实际连接到数据库通常是延迟加载的，并且是通过对数据库的第一次语句执行创建的。

`DB`结构的指针提供了`Ping`方法，通常对数据库进行幂等调用。`Ping`方法的变体是`PingContext`，它只是添加了取消或超时数据库调用的能力。请注意，如果`Ping`函数失败，连接将从数据库池中移除。

`DB`结构的指针还提供了`Conn`方法，用于从数据库池中检索连接。通过使用连接，您实际上保证使用相同的数据库会话。同样，`DB`结构的指针包含`PingContext`方法，`Conn`指针提供了`PingContext`方法来检查连接是否仍然活动。

# 执行语句

在以前的示例中，我们已经学习了如何连接和验证与数据库的连接。本示例将描述如何执行针对数据库的语句。

# 准备工作

通过在终端中调用`go version`命令来验证 Go 是否已正确安装。如果命令失败，请按照本章第一篇中的*准备工作*部分进行操作。

按照本章第一篇中的说明设置 PostgreSQL 服务器。

# 如何做...

1.  对您的示例数据库运行以下 SQL 脚本：

```go
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
```

1.  打开控制台并创建文件夹`chapter08/recipe03`。

1.  导航到目录。

1.  创建`statement.go`文件，内容如下：

```go
        package main

        import (
          "database/sql"
          "fmt"
          _ "github.com/lib/pq"
        )

        const sel = "SELECT * FROM post;"
        const trunc = "TRUNCATE TABLE post;"
        const ins = "INSERT INTO post(ID,TITLE,CONTENT)
                     VALUES (1,'Title 1','Content 1'),
                     (2,'Title 2','Content 2') "

        func main() {
          db := createConnection()
          defer db.Close()

          _, err := db.Exec(trunc)
          if err != nil {
            panic(err)
          }
          fmt.Println("Table truncated.")
          r, err := db.Exec(ins)
          if err != nil {
            panic(err)
          }
          affected, err := r.RowsAffected()
          if err != nil {
            panic(err)
          }
          fmt.Printf("Inserted rows count: %d\n",
                     affected)

          rs, err := db.Query(sel)
          if err != nil {
            panic(err)
          }
          count := 0
          for rs.Next() {
            count++
          }
          fmt.Printf("Total of %d was selected.\n", count)
        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run statement.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/17b952d6-d23c-442a-bfb1-cbb262c3e22b.png)

# 工作原理...

通常，我们可以执行两种类型的语句。对于第一种类型的语句，我们不期望任何行作为结果，最终我们得到的是没有输出或者只是受影响的行数。这种类型的语句通过`DB`结构指针上的`Exec`方法执行。在前面的示例代码中，我们有`TRUNCATE`和`INSERT`语句。但是这种方式也可以执行 DDL 和 DCL 语句。

有四种主要的语句类别：

+   **DDL**（**数据定义语言**）：此语言允许您创建和修改数据库模式

+   **DML**（**数据建模语言**）：此语言帮助您修改数据

+   **DCL**（**数据控制语言**）：此语言定义了对对象的访问控制

+   **TCL**（**事务控制语言**）：此语言控制事务。

第二种类型是我们期望以行的形式得到结果的语句；这些通常被称为查询。这种类型的语句通常通过`Query`或`QueryContext`方法执行。

# 使用准备好的语句

准备好的语句带来了安全性、效率和便利性。当然，可以使用它们与 Go 标准库一起使用；本示例将展示如何使用。

# 准备工作

通过在终端中调用`go version`命令来验证 Go 是否已正确安装。如果命令失败，请按照本章第一篇中的*准备工作*部分进行操作。

按照本章第一篇中的说明设置 PostgreSQL 服务器。

# 如何做...

1.  对您的示例数据库运行以下 SQL 脚本：

```go
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
```

1.  打开控制台并创建文件夹`chapter08/recipe04`。

1.  导航到目录。

1.  创建`prepared.go`文件，内容如下：

```go
        package main

        import (
          "database/sql"
          "fmt"
          _ "github.com/lib/pq"
        )

        const trunc = "TRUNCATE TABLE post;"
        const ins = "INSERT INTO post(ID,TITLE,CONTENT)
                     VALUES ($1,$2,$3)"

        var testTable = []struct {
          ID int
          Title string
          Content string
        }{
          {1, "Title One", "Content of title one"},
          {2, "Title Two", "Content of title two"},
          {3, "Title Three", "Content of title three"},
        }

        func main() {
          db := createConnection()
          defer db.Close()

          // Truncate table
          _, err := db.Exec(trunc)
          if err != nil {
            panic(err)
          }

          stm, err := db.Prepare(ins)
          if err != nil {
            panic(err)
          }

          inserted := int64(0)
          for _, val := range testTable {
            fmt.Printf("Inserting record ID: %d\n", val.ID)
            // Execute the prepared statement
            r, err := stm.Exec(val.ID, val.Title, val.Content)
            if err != nil {
              fmt.Printf("Cannot insert record ID : %d\n",
                         val.ID)
            }
            if affected, err := r.RowsAffected(); err == nil {
              inserted = inserted + affected
            }
          }

          fmt.Printf("Result: Inserted %d rows.\n", inserted)

        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run prepared.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/f93601d9-2fb8-4db8-a3dd-e263f03b0cf0.png)

# 工作原理...

要创建准备好的语句，需要调用指向`DB`结构的`Prepare`方法。之后，使用给定的参数调用`Stmt`指针上的`Exec`或`Query`方法。

准备好的语句是在`DB`指针的范围内创建的，但是在连接池中的特定连接上。语句记住了使用过的连接，并且在调用时尝试使用相同的连接。如果连接忙或已关闭，则重新创建准备好的语句并在新连接上调用语句。

如果在打开的事务`*Tx`中使用准备好的语句，则情况会发生变化，在这种情况下，准备好的语句绑定到与事务相关的一个连接。

请注意，事务中准备的语句不能与 DB 指针一起使用，反之亦然。

通常，准备好的语句的工作方式是在数据库端创建语句。数据库返回准备好的语句的标识符。准备好的语句在以下调用期间执行，并且只提供语句的参数。

# 取消挂起的查询

在某些情况下，您需要取消长时间运行的语句以限制资源的消耗，或者仅当结果不相关或语句运行时间过长时。自 Go 1.8 以来，取消查询是可能的。本配方解释了如何使用此功能。

# 准备工作

通过在终端中调用`go version`命令验证 Go 是否已正确安装。如果命令失败，请按照本章第一个配方中的*准备工作*部分进行操作。

按照本章第一个配方中提到的方式设置 PostgreSQL 服务器。

# 操作步骤...

1.  对您的示例数据库运行以下 SQL 脚本：

```go
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES
                        (1,'Title One','Content One'),
                        (2,'Title Two','Content Two');
```

1.  打开控制台并创建文件夹`chapter08/recipe05`。

1.  导航到目录。

1.  使用以下内容创建`cancelable.go`文件：

```go
        package main

        import (
          "context"
          "database/sql"
          "fmt"
          "time"
          _ "github.com/lib/pq"
        )

        const sel = "SELECT * FROM post p CROSS JOIN
           (SELECT 1 FROM generate_series(1,1000000)) tbl"

        func main() {
          db := createConnection()
          defer db.Close()

          ctx, canc := context.WithTimeout(context.Background(),
                                           20*time.Microsecond)
          rows, err := db.QueryContext(ctx, sel)
          canc() //cancel the query
          if err != nil {
            fmt.Println(err)
            return
          }
          defer rows.Close()
          count := 0
          for rows.Next() {
            if rows.Err() != nil {
              fmt.Println(rows.Err())
              continue
            }
            count++
          }

          fmt.Printf("%d rows returned\n", count)

        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run cancelable.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/dd8da9ab-b8ad-4b5b-bf43-3f0d766910ea.png)

# 工作原理...

`database/sql`包提供了取消挂起语句的可能性。`DB`结构指针的所有名为`XXXContext`的方法都会消耗上下文，并且可以取消挂起的语句。

只有在驱动程序支持`Context`变体时才能取消语句。如果不支持，将执行不带`Context`的变体。

使用`Context`变体和`context.WithTimeout`，您可以创建语句调用的超时。

请注意，示例代码执行以错误`pq: canceling statement due to user request`结束，这与调用查询后立即调用的`CancelFunc`相对应。

# 读取查询结果元数据

除了数据本身，查询结果还包含与结果集相关的元数据。这包含有关列名、类型和数据的其他信息。本配方将解释如何检索数据。

# 准备工作

通过在终端中调用`go version`命令验证 Go 是否已正确安装。如果命令失败，请按照本章第一个配方中的*准备工作*部分进行操作。

按照本章第一个配方中提到的方式设置 PostgreSQL 服务器。

# 操作步骤...

1.  对您的示例数据库运行以下 SQL 脚本：

```go
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES
                        (1,'Title One','Content One'),
                        (2,'Title Two','Content Two');

```

1.  打开控制台并创建文件夹`chapter08/recipe06`。

1.  导航到目录。

1.  使用以下内容创建`metadata.go`文件：

```go
        package main

        import (
          "database/sql"
          "fmt"
          _ "github.com/lib/pq"
        )

        const sel = "SELECT * FROM post p"

        func main() {

          db := createConnection()
          defer db.Close()

          rs, err := db.Query(sel)
          if err != nil {
            panic(err)
          }
          defer rs.Close()
          columns, err := rs.Columns()
          if err != nil {
            panic(err)
          }
          fmt.Printf("Selected columns: %v\n", columns)

          colTypes, err := rs.ColumnTypes()
          if err != nil {
            panic(err)
          }
          for _, col := range colTypes {
            fmt.Println()
            fmt.Printf("%+v\n", col)
          }

        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run metadata.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/48545a27-4614-44a1-a20b-5abdf0ae7f82.png)

# 工作原理...

`DB`结构指针的`Query`和`QueryContext`方法会导致`Rows`结构指针。`Rows`指针提供`Columns`和`ColumnTypes`方法，其中包含有关返回结果集结构的信息。

`Columns`方法返回带有列名的字符串切片。

`ColumnTypes`方法返回`ColumnType`指针的切片，其中包含有关返回结果集的更丰富信息。上述代码打印出了`ColumnType`指针公开的详细信息。

# 从查询结果中检索数据

在与数据库交互时，基本部分是通过执行查询来提取数据。本配方将说明使用标准库`database/sql`包时如何执行此操作。

# 准备工作

验证 Go 是否已正确安装，通过在终端中调用`go version`命令。如果命令失败，请按照本章第一个配方中的*准备工作*部分进行操作。

按照本章第一个配方中的说明设置 PostgreSQL 服务器。

# 操作步骤...

1.  对样本数据库运行以下 SQL 脚本：

```go
       DROP TABLE IF EXISTS post;
       CREATE TABLE post (
         ID serial,
         TITLE varchar(40),
         CONTENT varchar(255),
         CONSTRAINT pk_post PRIMARY KEY(ID)
       );
       SELECT * FROM post;
       INSERT INTO post(ID,TITLE,CONTENT) VALUES
                       (1,'Title One','Content One'),
                       (2,NULL,'Content Two');
```

1.  打开控制台并创建文件夹`chapter08/recipe07`。

1.  导航到目录。

1.  创建`data.go`文件，内容如下：

```go
        package main

        import (
          "database/sql"
          "fmt"
          _ "github.com/lib/pq"
        )

        const sel = `SELECT title,content FROM post;
        SELECT 1234 NUM; `

        const selOne = "SELECT title,content FROM post
                        WHERE ID = $1;"

        type Post struct {
          Name sql.NullString
          Text sql.NullString
        }

        func main() {
          db := createConnection()
          defer db.Close()

          rs, err := db.Query(sel)
          if err != nil {
            panic(err)
          }
          defer rs.Close()

          posts := []Post{}
          for rs.Next() {
            if rs.Err() != nil {
              panic(rs.Err())
            }
            p := Post{}
            if err := rs.Scan(&p.Name, &p.Text); err != nil {
              panic(err)
            }
            posts = append(posts, p)
          }

          var num int
          if rs.NextResultSet() {
            for rs.Next() {
              if rs.Err() != nil {
                panic(rs.Err())
              }
              rs.Scan(&num)
            }
          }

          fmt.Printf("Retrieved posts: %+v\n", posts)
          fmt.Printf("Retrieved number: %d\n", num)

          row := db.QueryRow(selOne, 100)
          or := Post{}
          if err := row.Scan(&or.Name, &or.Text); err != nil {
            fmt.Printf("Error: %s\n", err.Error())
            return
          }

          fmt.Printf("Retrieved one post: %+v\n", or)

        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run data.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2ac9cc08-6adb-48da-b0a6-a89657d80791.png)

# 工作原理...

来自指向`DB`结构的`Query`方法的`Rows`指针提供了从结果集中读取和提取数据的方法。

请注意，首先应调用`Next`方法将光标移动到下一个结果行。`Next`方法如果有其他行则返回`true`，否则返回`false`。

在通过`Next`获取新行后，可以调用`Scan`方法将数据提取到变量中。变量的数量必须与`SELECT`中的列数匹配，否则`Scan`方法无法提取数据。

代码的重要部分是，在每次调用`Next`方法后，应调用`Err`方法来查找在读取下一行时是否出现错误。

上述示例故意对第二条记录使用了`NULL`值。`NULL`数据库值无法提取到不可为空类型，例如`string`，在这种情况下，必须使用`NullString`类型。

为了完整起见，示例代码涵盖了`QueryRow`方法，它与`Query`方法略有不同。这个方法返回指向`Row`结构的指针，该结构仅提供`Scan`方法。请注意，只有在调用`Scan`方法之后才能检测到没有行的情况。

# 将查询结果解析为映射

有时查询结果或表的结构不清晰，需要将结果提取到某种灵活的结构中。这就引出了这个配方，其中将介绍将值提取到与列名映射的灵活结构中。

# 准备工作

验证 Go 是否已正确安装，通过在终端中调用`go version`命令。如果命令失败，请按照本章第一个配方中的*准备工作*部分进行操作。

按照本章第一个配方中的说明设置 PostgreSQL 服务器。

# 操作步骤...

1.  对样本数据库运行以下 SQL 脚本：

```go
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES 
                        (1,NULL,'Content One'),
                        (2,'Title Two','Content Two');
```

1.  打开控制台并创建文件夹`chapter08/recipe08`。

1.  导航到目录。

1.  创建`querymap.go`文件，内容如下：

```go
        package main

        import (
          "database/sql"
          "fmt"
          _ "github.com/lib/pq"
        )

        const selOne = "SELECT id,title,content FROM post
                        WHERE ID = $1;"

        func main() {
          db := createConnection()
          defer db.Close()

          rows, err := db.Query(selOne, 1)
          if err != nil {
            panic(err)
          }
          cols, _ := rows.Columns()
          for rows.Next() {
            m := parseWithRawBytes(rows, cols)
            fmt.Println(m)
            m = parseToMap(rows, cols)
            fmt.Println(m)
          }
        }

        func parseWithRawBytes(rows *sql.Rows, cols []string)
                               map[string]interface{} {
          vals := make([]sql.RawBytes, len(cols))
          scanArgs := make([]interface{}, len(vals))
          for i := range vals {
            scanArgs[i] = &vals[i]
          }
          if err := rows.Scan(scanArgs...); err != nil {
            panic(err)
          }
          m := make(map[string]interface{})
          for i, col := range vals {
            if col == nil {
              m[cols[i]] = nil
            } else {
              m[cols[i]] = string(col)
            }
          }
          return m
        }

        func parseToMap(rows *sql.Rows, cols []string)
                        map[string]interface{} {
          values := make([]interface{}, len(cols))
          pointers := make([]interface{}, len(cols))
          for i := range values {
            pointers[i] = &values[i]
          }

          if err := rows.Scan(pointers...); err != nil {
            panic(err)
          }

          m := make(map[string]interface{})
          for i, colName := range cols {
            if values[i] == nil {
              m[colName] = nil
            } else {
              m[colName] = values[i]
            }
          }
          return m
        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run querymap.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/d69cc84f-33e3-48b3-9d36-1a85b6f52253.png)

# 工作原理...

请注意，上述代码表示了两种方法。`parseWithRawBytes`函数使用了首选方法，但它高度依赖于驱动程序的实现。它的工作方式是创建与结果中列数相同长度的`RawBytes`切片。因为`Scan`函数需要值的指针，所以我们需要创建指向`RawBytes`切片（字节切片的切片）的指针切片，然后将其传递给`Scan`函数。

提取成功后，我们只需重新映射值。在示例代码中，我们将其转换为`string`，因为如果`RawBytes`是目标，驱动程序使用`string`类型来存储值。请注意，存储值的形式取决于驱动程序的实现。

第二种方法`parseToMap`在第一种方法不起作用的情况下是可用的。它几乎使用相同的方法，但值的切片被定义为空接口的切片。这种方法依赖于驱动程序。驱动程序应确定要分配给值指针的默认类型。

# 处理事务

事务控制是在处理数据库时需要牢记的常见事情。本配方将向您展示如何使用`sql`包处理事务。

# 准备工作

通过在终端中调用`go version`命令来验证 Go 是否已正确安装。如果命令失败，请按照本章第一个配方中的*准备工作*部分进行操作。

设置 PostgreSQL 服务器，如本章第一个配方中所述。

# 如何做...

1.  对您的示例数据库运行以下 SQL 脚本：

```go
        DROP TABLE IF EXISTS post;
        CREATE TABLE post (
          ID serial,
          TITLE varchar(40),
          CONTENT varchar(255),
          CONSTRAINT pk_post PRIMARY KEY(ID)
        );
        SELECT * FROM post;
        INSERT INTO post(ID,TITLE,CONTENT) VALUES
                        (1,'Title One','Content One'),
                        (2,NULL,'Content Two');
```

1.  打开控制台并创建文件夹`chapter08/recipe09`。

1.  导航到目录。

1.  创建`transaction.go`文件，内容如下：

```go
        package main

        import (
          "database/sql"
          "fmt"
          _ "github.com/lib/pq"
        )

        const selOne = "SELECT id,title,content FROM post
                        WHERE ID = $1;"
        const insert = "INSERT INTO post(ID,TITLE,CONTENT)
                VALUES (4,'Transaction Title','Transaction Content');"

        type Post struct {
          ID int
          Title string
          Content string
        }

        func main() {
          db := createConnection()
          defer db.Close()

          tx, err := db.Begin()
          if err != nil {
            panic(err)
          }
          _, err = tx.Exec(insert)
          if err != nil {
            panic(err)
          }
          p := Post{}
          // Query in other session/transaction
          if err := db.QueryRow(selOne, 4).Scan(&p.ID,
                &p.Title, &p.Content); err != nil {
            fmt.Println("Got error for db.Query:" + err.Error())
          }
          fmt.Println(p)
          // Query within transaction
          if err := tx.QueryRow(selOne, 4).Scan(&p.ID,
                 &p.Title, &p.Content); err != nil {
            fmt.Println("Got error for db.Query:" + err.Error())
          }
          fmt.Println(p)
          // After commit or rollback the
          // transaction need to recreated.
          tx.Rollback()

        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@
                      localhost:5432/example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run transaction.go`执行代码。

1.  看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/237bdb28-3ba6-4a4a-8c08-f1212e8f43fc.png)

# 工作原理...

正如前面的代码所示，事务处理非常简单。`DB`结构指针的`Begin`方法创建具有默认隔离级别的事务（取决于驱动程序）。事务本质上保留在单个连接上，并由返回的`Tx`结构指针表示。

指针`Tx`实现了`DB`结构指针可用的所有方法；唯一的例外是所有操作都在事务中完成（如果数据库能够在事务中处理语句）。通过在`Tx`结构指针上调用`Rollback`或`Commit`方法结束事务。在此调用之后，事务结束，其他操作将以错误`ErrTxDone`结束。

`DB`结构指针上还有一个有用的方法叫做`BeginTx`，它创建了事务`Tx`结构指针，同时也增强了给定的上下文。如果上下文被取消，事务将被回滚（进一步的`Commit`调用将导致错误）。`BeginTx`还消耗了`TxOptions`指针，这是可选的，可以定义隔离级别。

# 执行存储过程和函数

处理存储过程和函数总是比通常的语句更复杂，特别是如果过程包含自定义类型。标准库提供了处理这些的 API，但存储过程调用的支持程度取决于驱动程序的实现。本配方将展示一个非常简单的函数/过程调用。

# 准备工作

通过在终端中调用`go version`命令来验证 Go 是否已正确安装。如果命令失败，请按照本章第一个配方中的*准备工作*部分进行操作。

设置 PostgreSQL 服务器，如本章第一个配方中所述。

# 如何做...

1.  对您的示例数据库运行以下 SQL 脚本：

```go
        CREATE OR REPLACE FUNCTION format_name
        (firstname Text,lastname Text,age INT) RETURNS 
        VARCHAR AS $$
        BEGIN
          RETURN trim(firstname) ||' '||trim(lastname) ||' ('||age||')';
        END;
        $$ LANGUAGE plpgsql;
```

1.  打开控制台并创建文件夹`chapter08/recipe10`。

1.  导航到目录。

1.  创建`procedure.go`文件，内容如下：

```go
        package main

        import (
          "database/sql"
          "fmt"

          _ "github.com/go-sql-driver/mysql"
          _ "github.com/lib/pq"
        )

        const call = "select * from format_name($1,$2,$3)"

        const callMySQL = "CALL simpleproc(?)"

        type Result struct {
          Name string
          Category int
        }

        func main() {
          db := createConnection()
          defer db.Close()
          r := Result{}

          if err := db.QueryRow(call, "John", "Doe",
                    32).Scan(&r.Name); err != nil {
            panic(err)
          }
          fmt.Printf("Result is: %+v\n", r)
        }

        func createConnection() *sql.DB {
          connStr := "postgres://postgres:postgres@localhost:5432
                      /example?sslmode=disable"
          db, err := sql.Open("postgres", connStr)
          if err != nil {
            panic(err)
          }
          err = db.Ping()
          if err != nil {
            panic(err)
          }
          return db
        }
```

1.  通过`go run procedure.go`执行代码。

1.  看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/25194205-e33a-4b71-b9d9-e9653189ff44.png)

# 工作原理...

存储过程的调用高度依赖于驱动程序和数据库。请注意，在 PostgreSQL 数据库上检索结果与查询表非常相似。调用`DB`结构指针的`Query`或`QueryRow`方法，可以解析出结果行或行指针以获取值。

如果需要调用存储过程，MySQL 驱动程序将使用`CALL`语句。

几乎所有驱动程序的一般问题都是存储过程的`OUTPUT`参数。Go 1.9 增加了对这些参数的支持，但常用数据库的大多数驱动程序尚未实现这一功能。因此，解决方案可能是使用具有非标准 API 的驱动程序。

`OUTPUT`参数应该工作的方式是，存储过程调用将使用`database/sql`包中`Named`函数的`NamedArg`参数类型。`NamedArg`结构体的`Value`字段应该是`Out`类型，其中包含`Dest`字段，用于存放`OUTPUT`参数的实际值。
