# Go 编程秘籍第二版（一）

> 原文：[`zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0`](https://zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

感谢您选择这本书！我希望它能成为开发人员快速查阅 Go 开发模式的便利参考。它旨在成为其他资源的伴侣和一个参考，希望在阅读一次后长久有用。本书中的每个配方都包括可用作参考或应用程序基础的工作、简单和经过测试的代码。本书涵盖了从基础到高级主题的各种内容。

# 这本书是为谁准备的

这本书面向 Web 开发人员、程序员和企业开发人员。假定具有 Go 语言的基本知识。对后端应用程序开发的经验并非必需，但可能有助于理解一些配方背后的动机。

这本书是为已经熟练的 Go 开发人员提供快速提醒、示例或参考的好资源。通过开源存储库，也可以快速与团队分享这些示例。如果你正在寻找 Go 编程中常见和不太常见问题的快速解决方案，这本书适合你。

# 本书涵盖了什么

第一章，“I/O 和文件系统”，涵盖了常见的 Go I/O 接口，并探讨了与文件系统的工作。这包括临时文件、模板和 CSV 文件。

第二章，“命令行工具”，介绍了通过命令行接受用户输入，并探讨了处理常见数据类型如 TOML、YAML 和 JSON。

第三章，“数据转换和组合”，演示了在 Go 接口和数据类型之间进行转换和转换的方法。它还展示了 Go 的编码策略和一些功能设计模式。

第四章，“Go 中的错误处理”，展示了处理 Go 中错误的策略。它探讨了如何传递错误、处理错误和记录错误。

第五章，“网络编程”，演示了各种网络原语的使用，如 UDP 和 TCP/IP。它还探讨了域名系统（DNS）、处理原始电子邮件消息以及基本的远程过程调用（RPC）。

第六章，“关于数据库和存储的一切”，涉及了用于访问数据存储系统（如 MySQL）的各种存储库。它还演示了使用接口来将库与应用程序逻辑解耦。

第七章，“Web 客户端和 API”，实现了 Go HTTP 客户端接口、REST 客户端、OAuth2 客户端、装饰和扩展客户端以及 gRPC。

第八章，“Go 语言应用的微服务”，探讨了 web 处理程序、向处理程序传递状态、用户输入验证和中间件。

第九章，“测试 Go 代码”，着重于模拟、测试覆盖率、模糊测试、行为测试和有用的测试工具。

第十章，“并行和并发”，提供了通道和异步操作、原子值、Go 上下文对象和通道状态管理的参考。

第十一章，“分布式系统”，实现了服务发现、Docker 容器化、度量和监控以及编排。它主要涉及 Go 应用程序的部署和生产。

第十二章，“响应式编程和数据流”，探讨了响应式和数据流应用程序、Kafka 和分布式消息队列以及 GraphQL 服务器。

第十三章，*无服务器编程*，涉及在不维护服务器的情况下部署 Go 应用程序。这包括使用 Google App Engine，Firebase，Lambda 以及在无服务器环境中登录。

第十四章，*性能改进，技巧和窍门*，涉及基准测试，识别瓶颈，优化和改进 Go 应用程序的 HTTP 性能。

# 为了充分利用本书

要使用本书，您需要以下内容：

+   Unix 编程环境。

+   Go 1.x 系列的最新版本。

+   互联网连接。

+   根据每章描述安装附加软件包的权限。

+   每个配方的先决条件和其他安装要求都在各章的*技术要求*部分中提到。

# 下载示例代码文件

您可以从您在[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名并按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition`](https://github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition)。我们还有其他代码包，可以从我们丰富的书籍和视频目录中获得，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。请查看！

# 代码实例

访问以下链接以查看代码运行的视频：[`bit.ly/2J2uqQ3`](http://bit.ly/2J2uqQ3)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码字，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“`bytes`库在处理数据时提供了许多方便的功能。”

代码块设置如下：

```go
                b, err := ioutil.ReadAll(r)
                if err != nil {
                    return "", err
                }
                return string(b), nil
        }
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体设置：

```go
        package bytestrings

        import (
                "bytes"
                "io"
                "io/ioutil"
        )
```

任何命令行输入或输出都以以下方式编写：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/Chapter01/interfaces
```

**粗体**：表示新术语，重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会以这种方式出现。

技巧和窍门会以这种方式出现。

# 各节

在本书中，您会经常看到几个标题（*准备工作*，*如何做…*，*工作原理…*，*还有更多…*和*另请参阅*）。

为了清晰地说明如何完成一个配方，使用以下各节：

# 准备工作

本节告诉您在配方中可以期待什么，并描述了为配方设置任何所需软件或任何预备设置的方法。

# 如何做…

本节包含遵循配方所需的步骤。

# 工作原理…

本节通常包括对上一节中发生的事情的详细解释。

# 还有更多…

本节包含有关配方的其他信息，以使您对配方更加了解。

# 另请参阅

本节为配方提供了其他有用信息的链接。


# 第一章：I/O 和文件系统

Go 提供了对基本和复杂 I/O 的出色支持。本章中的配方将探讨用于处理 I/O 的常见 Go 接口，并向您展示如何使用它们。Go 标准库经常使用这些接口，并且它们将被本书中的配方使用。

您将学习如何处理内存中的数据和流式数据。您将看到有关处理文件、目录和 CSV 格式的示例。临时文件配方介绍了一种处理文件的机制，而无需处理名称冲突等开销。最后，我们将探讨 Go 标准模板，包括纯文本和 HTML。

这些配方应该为使用接口来表示和修改数据奠定基础，并应该帮助您以抽象和灵活的方式思考数据。

在本章中，将介绍以下配方：

+   使用常见的 I/O 接口

+   使用 bytes 和 strings 包

+   处理目录和文件

+   处理 CSV 格式

+   使用临时文件

+   使用 text/template 和 html/template

# 技术要求

为了继续本章中的所有配方，请根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开终端或控制台应用程序，并创建并转到一个项目目录，例如`~/projects/go-programming-cookbook`。所有代码将从该目录运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`中，如下所示。建议您从该目录中工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 使用常见的 I/O 接口

Go 语言提供了许多 I/O 接口，这些接口在整个标准库中使用。最佳实践是尽可能使用这些接口，而不是直接传递结构或其他类型。我们将在本配方中探讨的两个强大接口是`io.Reader`和`io.Writer`接口。这些接口在整个标准库中使用，了解如何使用它们将使您成为更好的 Go 开发人员。

`Reader`和`Writer`接口如下所示：

```go
type Reader interface {
        Read(p []byte) (n int, err error)
}

type Writer interface {
        Write(p []byte) (n int, err error)
}
```

Go 还可以轻松地组合接口。例如，看一下以下代码：

```go
type Seeker interface {
        Seek(offset int64, whence int) (int64, error)
}

type ReadSeeker interface {
        Reader
        Seeker
}
```

本配方还将探讨一个名为`Pipe()`的`io`函数，如下所示：

```go
func Pipe() (*PipeReader, *PipeWriter)
```

本书的其余部分将使用这些接口。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter1/interfaces`的新目录。

1.  转到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/interfaces 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/interfaces    
```

1.  从`~/projects/go-programming-cookbook-original/chapter1/interfaces`复制测试，或者使用这个作为练习来编写一些您自己的代码！

1.  创建一个名为`interfaces.go`的文件，内容如下：

```go
        package interfaces

        import (
                "fmt"
                "io"
                "os"
        )

        // Copy copies data from in to out first directly,
        // then using a buffer. It also writes to stdout
        func Copy(in io.ReadSeeker, out io.Writer) error {
                // we write to out, but also Stdout
                w := io.MultiWriter(out, os.Stdout)

                // a standard copy, this can be dangerous if there's a 
                // lot of data in in
                if _, err := io.Copy(w, in); err != nil {
                    return err
                }

                in.Seek(0, 0)

                // buffered write using 64 byte chunks
                buf := make([]byte, 64)
                if _, err := io.CopyBuffer(w, in, buf); err != nil {
                    return err
                }

                // lets print a new line
                fmt.Println()

                return nil
        }
```

1.  创建一个名为`pipes.go`的文件，内容如下：

```go
        package interfaces

        import (
                "io"
                "os"
        )

        // PipeExample helps give some more examples of using io  
        //interfaces
        func PipeExample() error {
                // the pipe reader and pipe writer implement
                // io.Reader and io.Writer
                r, w := io.Pipe()

                // this needs to be run in a separate go routine
                // as it will block waiting for the reader
                // close at the end for cleanup
                go func() {
                    // for now we'll write something basic,
                    // this could also be used to encode json
                    // base64 encode, etc.
                    w.Write([]byte("test\n"))
                    w.Close()
                }()

                if _, err := io.Copy(os.Stdout, r); err != nil {
                    return err
                }
                return nil
        }
```

1.  创建一个名为`example`的新目录并进入该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
             "bytes"
             "fmt"

             "github.com/PacktPublishing/
              Go-Programming-Cookbook-Second-Edition/
              chapter1/bytestrings"
        )

        func main() {
                in := bytes.NewReader([]byte("example"))
                out := &bytes.Buffer{}
                fmt.Print("stdout on Copy = ")
                if err := interfaces.Copy(in, out); err != nil {
                        panic(err)
                }

                fmt.Println("out bytes buffer =", out.String())

                fmt.Print("stdout on PipeExample = ")
                if err := interfaces.PipeExample(); err != nil {
                        panic(err)
                }
        }
```

1.  运行`go run .`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该会看到以下输出：

```go
$ go run .
stdout on Copy = exampleexample
out bytes buffer = exampleexample
stdout on PipeExample = test
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 它是如何工作的...

`Copy()`函数在接口之间复制字节，并将该数据视为流。将数据视为流在许多实际用途中非常有用，特别是在处理网络流量或文件系统时。`Copy()`函数还创建了一个`MultiWriter`接口，它将两个写入流组合在一起，并使用`ReadSeeker`两次写入它们。如果使用了`Reader`接口，而不是看到`exampleexample`，您只会看到`example`，尽管将数据复制到`MultiWriter`接口两次。如果您的流无法适应内存，还可以使用缓冲写入。

`PipeReader`和`PipeWriter`结构实现了`io.Reader`和`io.Writer`接口。它们连接在一起，创建一个内存管道。管道的主要目的是从流中读取数据，同时将相同流中的数据写入到不同的源。本质上，它将两个流合并成一个管道。

Go 接口是一种干净的抽象，用于包装执行常见操作的数据。这在进行 I/O 操作时变得明显，因此`io`包是学习接口组合的一个很好的资源。`pipe`包通常被低估，但在链接输入和输出流时提供了很大的灵活性和线程安全性。

# 使用`bytes`和`strings`包

`bytes`和`strings`包提供了许多有用的辅助函数，用于处理和转换字符串和字节类型的数据。它们允许创建与许多常见 I/O 接口一起使用的缓冲区。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter1/bytestrings`的新目录。

1.  导航到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/bytestrings 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/bytestrings    
```

1.  从`~/projects/go-programming-cookbook-original/chapter1/bytestrings`复制测试，或者将其用作练习编写一些自己的代码！

1.  创建一个名为`buffer.go`的文件，其中包含以下内容：

```go
        package bytestrings

        import (
                "bytes"
                "io"
                "io/ioutil"
        )

        // Buffer demonstrates some tricks for initializing bytes    
        //Buffers
        // These buffers implement an io.Reader interface
        func Buffer(rawString string) *bytes.Buffer {

                // we'll start with a string encoded into raw bytes
                rawBytes := []byte(rawString)

                // there are a number of ways to create a buffer from 
                // the raw bytes or from the original string
                var b = new(bytes.Buffer)
                b.Write(rawBytes)

                // alternatively
                b = bytes.NewBuffer(rawBytes)

                // and avoiding the initial byte array altogether
                b = bytes.NewBufferString(rawString)

                return b
        }

        // ToString is an example of taking an io.Reader and consuming 
        // it all, then returning a string
        func toString(r io.Reader) (string, error) {
                b, err := ioutil.ReadAll(r)
                if err != nil {
                    return "", err
                }
                return string(b), nil
        }
```

1.  创建一个名为`bytes.go`的文件，其中包含以下内容：

```go
        package bytestrings

        import (
                "bufio"
                "bytes"
                "fmt"
        )

        // WorkWithBuffer will make use of the buffer created by the
        // Buffer function
        func WorkWithBuffer() error {
                rawString := "it's easy to encode unicode into a byte 
                              array"

                b := Buffer(rawString)

                // we can quickly convert a buffer back into byes with
                // b.Bytes() or a string with b.String()
                fmt.Println(b.String())

                // because this is an io Reader we can make use of  
                // generic io reader functions such as
                s, err := toString(b)
                if err != nil {
                    return err
                }
                fmt.Println(s)

                // we can also take our bytes and create a bytes reader
                // these readers implement io.Reader, io.ReaderAt, 
                // io.WriterTo, io.Seeker, io.ByteScanner, and 
                // io.RuneScanner interfaces
                reader := bytes.NewReader([]byte(rawString))

                // we can also plug it into a scanner that allows 
                // buffered reading and tokenzation
                scanner := bufio.NewScanner(reader)
                scanner.Split(bufio.ScanWords)

                // iterate over all of the scan events
                for scanner.Scan() {
                    fmt.Print(scanner.Text())
                }

                return nil
        }
```

1.  创建一个名为`string.go`的文件，其中包含以下内容：

```go
        package bytestrings

        import (
                "fmt"
                "io"
                "os"
                "strings"
        )

        // SearchString shows a number of methods
        // for searching a string
        func SearchString() {
                s := "this is a test"

                // returns true because s contains
                // the word this
                fmt.Println(strings.Contains(s, "this"))

                // returns true because s contains the letter a
                // would also match if it contained b or c
                fmt.Println(strings.ContainsAny(s, "abc"))

                // returns true because s starts with this
                fmt.Println(strings.HasPrefix(s, "this"))

                // returns true because s ends with this
                fmt.Println(strings.HasSuffix(s, "test"))
                }

        // ModifyString modifies a string in a number of ways
        func ModifyString() {
                s := "simple string"

                // prints [simple string]
                fmt.Println(strings.Split(s, " "))

                // prints "Simple String"
                fmt.Println(strings.Title(s))

                // prints "simple string"; all trailing and
                // leading white space is removed
                s = " simple string "
                fmt.Println(strings.TrimSpace(s))
        }

        // StringReader demonstrates how to create
        // an io.Reader interface quickly with a string
        func StringReader() {
                s := "simple stringn"
                r := strings.NewReader(s)

                // prints s on Stdout
                io.Copy(os.Stdout, r)
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter1/bytestrings"

        func main() {
                err := bytestrings.WorkWithBuffer()
                if err != nil {
                        panic(err)
                }

                // each of these print to stdout
                bytestrings.SearchString()
                bytestrings.ModifyString()
                bytestrings.StringReader() 
        }
```

1.  运行`go run .`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run .
it's easy to encode unicode into a byte array ??
it's easy to encode unicode into a byte array ??
it'seasytoencodeunicodeintoabytearray??true
true
true
true
[simple string]
Simple String
simple string
simple string
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 它是如何工作的...

`bytes`库在处理数据时提供了许多便利函数。例如，与字节数组相比，缓冲区在处理流处理库或方法时更加灵活。创建缓冲区后，它可以用于满足`io.Reader`接口，以便您可以利用`ioutil`函数来操作数据。对于流应用程序，您可能希望使用缓冲区和扫描器。`bufio`包在这些情况下非常有用。有时，对于较小的数据集或者在计算机上有大量内存时，使用数组或切片更为合适。

在使用这些基本类型时，Go 在转换数据之间的接口方面提供了很大的灵活性——在字符串和字节之间进行转换相对简单。在处理字符串时，`strings`包提供了许多便利函数，用于处理、搜索和操作字符串。在某些情况下，一个良好的正则表达式可能是合适的，但大多数情况下，`strings`和`strconv`包就足够了。`strings`包允许您将字符串看起来像标题，将其拆分为数组，或修剪空白。它还提供了自己的`Reader`接口，可以用于代替`bytes`包的读取器类型。

# 处理目录和文件

在切换平台（例如 Windows 和 Linux）时，处理目录和文件可能会很困难。Go 在`os`和`ioutils`包中提供了跨平台支持，以处理文件和目录。我们已经看到了`ioutils`的示例，现在我们将探讨如何以另一种方式使用它们！

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter1/filedirs`的新目录。

1.  进入此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/filedirs 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/filedirs    
```

1.  从`~/projects/go-programming-cookbook-original/chapter1/filedirs`复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`dirs.go`的文件，其中包含以下内容：

```go
        package filedirs

        import (
                "errors"
                "io"
                "os"
        )

        // Operate manipulates files and directories
        func Operate() error {
                // this 0755 is similar to what you'd see with Chown
                // on a command line this will create a director 
                // /tmp/example, you may also use an absolute path 
                // instead of a relative one
                if err := os.Mkdir("example_dir", os.FileMode(0755)); 
                err !=  nil {
                        return err
                }

                // go to the /tmp directory
                if err := os.Chdir("example_dir"); err != nil {
                        return err
                }

                // f is a generic file object
                // it also implements multiple interfaces
                // and can be used as a reader or writer
                // if the correct bits are set when opening
                f, err := os.Create("test.txt")
                if err != nil {
                        return err
                }

                // we write a known-length value to the file and 
                // validate that it wrote correctly
                value := []byte("hellon")
                count, err := f.Write(value)
                if err != nil {
                        return err
                }
                if count != len(value) {
                        return errors.New("incorrect length returned 
                        from write")
                }

                if err := f.Close(); err != nil {
                        return err
                }

                // read the file
                f, err = os.Open("test.txt")
                if err != nil {
                        return err
                }

                io.Copy(os.Stdout, f)

                if err := f.Close(); err != nil {
                        return err
                }

                // go to the /tmp directory
                if err := os.Chdir(".."); err != nil {
                        return err
                }

                // cleanup, os.RemoveAll can be dangerous if you
                // point at the wrong directory, use user input,
                // and especially if you run as root
                if err := os.RemoveAll("example_dir"); err != nil {
                        return err
                }

                return nil
        }
```

1.  创建一个名为`files.go`的文件，其中包含以下内容：

```go
        package filedirs

        import (
                "bytes"
                "io"
                "os"
                "strings"
        )

        // Capitalizer opens a file, reads the contents,
        // then writes those contents to a second file
                func Capitalizer(f1 *os.File, f2 *os.File) error {
                if _, err := f1.Seek(0, io.SeekStart); err != nil {
                        return err
                }

                var tmp = new(bytes.Buffer)

                if _, err := io.Copy(tmp, f1); err != nil {
                        return err
                }

                s := strings.ToUpper(tmp.String())

                if _, err := io.Copy(f2, strings.NewReader(s)); err != 
                nil {
                        return err
                }
                return nil
        }

        // CapitalizerExample creates two files, writes to one
        //then calls Capitalizer() on both
        func CapitalizerExample() error {
                f1, err := os.Create("file1.txt")
                if err != nil {
                        return err
                }

                if _, err := f1.Write([]byte(`this file contains a 
                number of words and new lines`)); err != nil {
                        return err
                }

                f2, err := os.Create("file2.txt")
                if err != nil {
                        return err
                }

                if err := Capitalizer(f1, f2); err != nil {
                        return err
                }

                if err := os.Remove("file1.txt"); err != nil {
                        return err
                }

                if err := os.Remove("file2.txt"); err != nil {
                        return err
                }

                return nil
        }
```

1.  创建一个名为`example`的新目录并进入该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter1/filedirs"

        func main() {
                if err := filedirs.Operate(); err != nil {
                        panic(err)
                }

                if err := filedirs.CapitalizerExample(); err != nil {
                        panic(err)
                }
        }
```

1.  运行`go run .`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run . 
hello
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 工作原理...

如果您熟悉 Unix 中的文件，Go 的`os`库应该会让您感到非常熟悉。您可以执行基本上所有常见的操作——`Stat`文件以收集属性，使用不同权限收集文件，并创建和修改目录和文件。在本示例中，我们对目录和文件进行了许多操作，然后在完成后进行了清理。

与处理内存流非常相似，处理文件对象也提供了许多便利函数，例如`Chown`、`Stat`和`Truncate`。熟悉文件的最简单方法是利用它们。在所有以前的示例中，我们都必须小心清理我们的程序。

在构建后端应用程序时，与文件的操作是非常常见的。文件可用于配置、秘钥、临时存储等。Go 使用`os`包封装了操作系统系统调用，并允许相同的函数在使用 Windows 或 Unix 时运行。

一旦您的文件被打开并存储在`File`结构中，它就可以轻松地传递到许多接口中（我们之前讨论过这些接口）。所有之前的示例都可以直接使用`os.File`结构，而不是缓冲区和内存数据流，以便在磁盘上存储的数据上进行操作。这对于某些技术可能很有用，例如使用单个写入调用同时将所有日志写入`stderr`和文件。

# 使用 CSV 格式

CSV 是一种常见的格式，用于操作数据。例如，将 CSV 文件导入或导出到 Excel 是常见的。Go `CSV`包操作数据接口，因此很容易将数据写入缓冲区、`stdout`、文件或套接字。本节中的示例将展示一些常见的将数据转换为 CSV 格式或从 CSV 格式中获取数据的方法。

# 如何做...

这些步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter1/csvformat`的新目录。

1.  进入此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/csvformat 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/csvformat    
```

1.  从`~/projects/go-programming-cookbook-original/chapter1/csvformat`复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`read_csv.go`的文件，其中包含以下内容：

```go
        package csvformat

        import (
                "bytes"
                "encoding/csv"
                "fmt"
                "io"
                "strconv"
        )

        // Movie will hold our parsed CSV
        type Movie struct {
                Title string
                Director string
                Year int
        }

        // ReadCSV gives shows some examples of processing CSV
        // that is passed in as an io.Reader
        func ReadCSV(b io.Reader) ([]Movie, error) {

                r := csv.NewReader(b)

                // These are some optional configuration options
                r.Comma = ';'
                r.Comment = '-'

                var movies []Movie

                // grab and ignore the header for now
                // we may also want to use this for a dictionary key or
                // some other form of lookup
                _, err := r.Read()
                if err != nil && err != io.EOF {
                        return nil, err
                }

                // loop until it's all processed
                for {
                        record, err := r.Read()
                        if err == io.EOF {
                                break
                        } else if err != nil {
                                return nil, err
                        }

                        year, err := strconv.ParseInt(record[2], 10, 
                        64)
                        if err != nil {
                                return nil, err
                        }

                        m := Movie{record[0], record[1], int(year)}
                        movies = append(movies, m)
                }
                return movies, nil
        }
```

1.  将此附加功能添加到`read_csv.go`中，如下所示：

```go
        // AddMoviesFromText uses the CSV parser with a string
        func AddMoviesFromText() error {
                // this is an example of us taking a string, converting
                // it into a buffer, and reading it 
                // with the csv package
                in := `
                - first our headers
                movie title;director;year released

                - then some data
                Guardians of the Galaxy Vol. 2;James Gunn;2017
                Star Wars: Episode VIII;Rian Johnson;2017
                `

                b := bytes.NewBufferString(in)
                m, err := ReadCSV(b)
                if err != nil {
                        return err
                }
                fmt.Printf("%#vn", m)
                return nil
        }
```

1.  创建一个名为`write_csv.go`的文件，其中包含以下内容：

```go
        package csvformat

        import (
                "bytes"
                "encoding/csv"
                "io"
                "os"
        )

        // A Book has an Author and Title
        type Book struct {
                Author string
                Title string
        }

        // Books is a named type for an array of books
        type Books []Book

        // ToCSV takes a set of Books and writes to an io.Writer
        // it returns any errors
        func (books *Books) ToCSV(w io.Writer) error {
                n := csv.NewWriter(w)
                err := n.Write([]string{"Author", "Title"})
                if err != nil {
                        return err
                }
                for _, book := range *books {
                        err := n.Write([]string{book.Author, 
                        book.Title})
                        if err != nil {
                                return err
                        }
                }

                n.Flush()
                return n.Error()
        }
```

1.  将以下附加功能添加到`write_csv.go`中，如下所示：

```go
        // WriteCSVOutput initializes a set of books
        // and writes the to os.Stdout
        func WriteCSVOutput() error {
                b := Books{
                        Book{
                                Author: "F Scott Fitzgerald",
                                Title: "The Great Gatsby",
                        },
                        Book{
                                Author: "J D Salinger",
                                Title: "The Catcher in the Rye",
                        },
                }

                return b.ToCSV(os.Stdout)
        }

        // WriteCSVBuffer returns a buffer csv for
        // a set of books
        func WriteCSVBuffer() (*bytes.Buffer, error) {
                b := Books{
                        Book{
                                Author: "F Scott Fitzgerald",
                                Title: "The Great Gatsby",
                        },
                        Book{
                                Author: "J D Salinger",
                                Title: "The Catcher in the Rye",
                        },
                }

                w := &bytes.Buffer{}
                err := b.ToCSV(w)
                return w, err
        }
```

1.  创建一个名为`example`的新目录并进入该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
                "fmt"

                "github.com/PacktPublishing/
                 Go-Programming-Cookbook-Second-Edition/
                 chapter1/csvformat"
        )

        func main() {
                if err := csvformat.AddMoviesFromText(); err != nil {
                        panic(err)
                }

                if err := csvformat.WriteCSVOutput(); err != nil {
                        panic(err)
                }

                buffer, err := csvformat.WriteCSVBuffer()
                if err != nil {
                        panic(err)
                }

                fmt.Println("Buffer = ", buffer.String())
        }
```

1.  运行`go run .`。

1.  您还可以运行以下命令：

```go
$ go build
$ ./example
```

您应该看到以下输出：

```go
$ go run . 
[]csvformat.Movie{csvformat.Movie{Title:"Guardians of the 
Galaxy Vol. 2", Director:"James Gunn", Year:2017},         
csvformat.Movie{Title:"Star Wars: Episode VIII", Director:"Rian 
Johnson", Year:2017}}
Author,Title
F Scott Fitzgerald,The Great Gatsby
J D Salinger,The Catcher in the Rye
Buffer = Author,Title
F Scott Fitzgerald,The Great Gatsby
J D Salinger,The Catcher in the Rye
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 工作原理...

为了学习如何读取 CSV 格式，我们首先将我们的数据表示为一个结构。在 Go 中，将数据格式化为结构非常有用，因为它使诸如编组和编码之类的事情相对简单。我们的读取示例使用电影作为我们的数据类型。该函数接受一个`io.Reader`接口，该接口将我们的 CSV 数据作为输入。这可以是文件或缓冲区。然后，我们使用该数据来创建和填充一个`Movie`结构，包括将年份转换为整数。我们还添加了选项到 CSV 解析器，以使用`;`（分号）作为分隔符和`-`（连字符）作为注释行。

接下来，我们以相同的思路进行探索，但是反过来。小说由标题和作者表示。我们初始化了一个小说数组，然后以 CSV 格式将特定的小说写入到`io.Writer`接口中。这可以是文件、`stdout`或缓冲区。

`CSV`包是一个很好的例子，说明为什么您希望将 Go 中的数据流视为实现常见接口。通过小幅调整，我们可以轻松更改数据的来源和目的地，并且可以在不使用过多内存或时间的情况下轻松操作 CSV 数据。例如，可以可能一次从数据流中读取一条记录，并一次以修改后的格式将其写入到另一个流中。这样做不会带来显著的内存或处理器使用。

稍后，当我们探索数据管道和工作池时，您将看到这些想法如何结合以及如何并行处理这些流。

# 使用临时文件

到目前为止，我们已经为许多示例创建并使用了文件。我们还必须手动处理清理、名称冲突等问题。临时文件和目录是处理这些情况的一种更快、更简单的方法。

# 如何做...

以下步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter1/tempfiles`的新目录。

1.  导航到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/tempfiles 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/tempfiles    
```

1.  从`~/projects/go-programming-cookbook-original/chapter1/tempfiles`复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`temp_files.go`的文件，内容如下：

```go
        package tempfiles

        import (
                "fmt"
                "io/ioutil"
                "os"
        )

        // WorkWithTemp will give some basic patterns for working
        // with temporary files and directories
        func WorkWithTemp() error {
                // If you need a temporary place to store files with 
                // the same name ie. template1-10.html a temp directory 
                //  is a good way to approach it, the first argument 
                // being blank means it will use create the directory                
                // in the location returned by 
                // os.TempDir()
                t, err := ioutil.TempDir("", "tmp")
                if err != nil {
                        return err
                }

                // This will delete everything inside the temp file 
                // when this function exits if you want to do this 
                //  later, be sure to return the directory name to the 
                // calling function
                defer os.RemoveAll(t)

                // the directory must exist to create the tempfile
                // created. t is an *os.File object.
                tf, err := ioutil.TempFile(t, "tmp")
                if err != nil {
                        return err
                }

                fmt.Println(tf.Name())

                // normally we'd delete the temporary file here, but 
                // because we're placing it in a temp directory, it 
                // gets cleaned up by the earlier defer

                return nil
        }
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter1/tempfiles"

        func main() {
                if err := tempfiles.WorkWithTemp(); err != nil {
                        panic(err)
                }
        }
```

1.  运行`go run .`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出（路径不同）：

```go
$ go run . 
/var/folders/kd/ygq5l_0d1xq1lzk_c7htft900000gn/T
/tmp764135258/tmp588787953
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 工作原理...

可以使用`ioutil`包来创建临时文件和目录。虽然您仍然必须自己删除文件，但使用`RemoveAll`是惯例，它将为您执行此操作，只需额外一行代码。

在编写测试时，强烈建议使用临时文件。它还对构建产物等非常有用。Go 的`ioutil`包将尝试默认遵守操作系统的偏好，但如果需要，它允许您回退到其他目录。

# 使用 text/template 和 html/template

Go 提供了丰富的模板支持。嵌套模板、导入函数、表示变量、迭代数据等都很简单。如果您需要比 CSV 写入器更复杂的东西，模板可能是一个很好的解决方案。

模板的另一个应用是用于网站。当我们想要将服务器端数据呈现给客户端时，模板非常合适。起初，Go 模板可能看起来令人困惑。本节将探讨使用模板、收集目录中的模板以及使用 HTML 模板。

# 如何做...

这些步骤涵盖了如何编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter1/templates`的新目录。

1.  导航到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/templates 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter1/templates    
```

1.  从`~/projects/go-programming-cookbook-original/chapter1/templates`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`templates.go`的文件，其中包含以下内容：

```go
        package templates

        import (
                "os"
                "strings"
                "text/template"
        )

        const sampleTemplate = `
                This template demonstrates printing a {{ .Variable | 
                printf "%#v" }}.

                {{if .Condition}}
                If condition is set, we'll print this
                {{else}}
                Otherwise, we'll print this instead
                {{end}}

                Next we'll iterate over an array of strings:
                {{range $index, $item := .Items}}
                {{$index}}: {{$item}}
                {{end}}

                We can also easily import other functions like 
                strings.Split
                then immediately used the array created as a result:
                {{ range $index, $item := split .Words ","}}
                {{$index}}: {{$item}}
                {{end}}

                Blocks are a way to embed templates into one another
                {{ block "block_example" .}}
                No Block defined!
                {{end}}

                {{/*
                This is a way
                to insert a multi-line comment
                */}}
`

        const secondTemplate = `
                {{ define "block_example" }}
                {{.OtherVariable}}
                {{end}}
`
```

1.  在`templates.go`的末尾添加一个函数，如下所示：

```go
        // RunTemplate initializes a template and demonstrates a 
        // variety of template helper functions
        func RunTemplate() error {
                data := struct {
                        Condition bool
                        Variable string
                        Items []string
                        Words string
                        OtherVariable string
                }{
                        Condition: true,
                        Variable: "variable",
                        Items: []string{"item1", "item2", "item3"},
                        Words: 
                        "another_item1,another_item2,another_item3",
                        OtherVariable: "I'm defined in a second 
                        template!",
                }

                funcmap := template.FuncMap{
                        "split": strings.Split,
                }

                // these can also be chained
                t := template.New("example")
                t = t.Funcs(funcmap)

                // We could use Must instead to panic on error
                // template.Must(t.Parse(sampleTemplate))
                t, err := t.Parse(sampleTemplate)
                if err != nil {
                        return err
                }

                // to demonstrate blocks we'll create another template
                // by cloning the first template, then parsing a second
                t2, err := t.Clone()
                if err != nil {
                        return err
                }

                t2, err = t2.Parse(secondTemplate)
                if err != nil {
                        return err
                }

                // write the template to stdout and populate it
                // with data
                err = t2.Execute(os.Stdout, &data)
                if err != nil {
                        return err
                }

                return nil
        }
```

1.  创建一个名为`template_files.go`的文件，其中包含以下内容：

```go
        package templates

        import (
                "io/ioutil"
                "os"
                "path/filepath"
                "text/template"
        )

        //CreateTemplate will create a template file that contains data
        func CreateTemplate(path string, data string) error {
                return ioutil.WriteFile(path, []byte(data), 
                os.FileMode(0755))
        }

        // InitTemplates sets up templates from a directory
        func InitTemplates() error {
                tempdir, err := ioutil.TempDir("", "temp")
                if err != nil {
                        return err
                }
                defer os.RemoveAll(tempdir)

                err = CreateTemplate(filepath.Join(tempdir, "t1.tmpl"), 
                `Template 1! {{ .Var1 }}
                {{ block "template2" .}} {{end}}
                {{ block "template3" .}} {{end}}
                `)
                if err != nil {
                        return err
                }

                err = CreateTemplate(filepath.Join(tempdir, "t2.tmpl"), 
                `{{ define "template2"}}Template 2! {{ .Var2 }}{{end}}
                `)
                if err != nil {
                        return err
                }

                err = CreateTemplate(filepath.Join(tempdir, "t3.tmpl"), 
                `{{ define "template3"}}Template 3! {{ .Var3 }}{{end}}
                `)
                if err != nil {
                        return err
                }

                pattern := filepath.Join(tempdir, "*.tmpl")

                // Parse glob will combine all the files that match 
                // glob and combine them into a single template
                tmpl, err := template.ParseGlob(pattern)
                if err != nil {
                        return err
                }

                // Execute can also work with a map instead
                // of a struct
                tmpl.Execute(os.Stdout, map[string]string{
                        "Var1": "Var1!!",
                        "Var2": "Var2!!",
                        "Var3": "Var3!!",
                 })

                 return nil
        }
```

1.  创建一个名为`html_templates.go`的文件，其中包含以下内容：

```go
        package templates

        import (
                "fmt"
                "html/template"
                "os"
        )

        // HTMLDifferences highlights some of the differences
        // between html/template and text/template
        func HTMLDifferences() error {
                t := template.New("html")
                t, err := t.Parse("<h1>Hello! {{.Name}}</h1>n")
                if err != nil {
                        return err
         }

                // html/template auto-escapes unsafe operations like 
                // javascript injection this is contextually aware and 
                // will behave differently
                // depending on where a variable is rendered
                err = t.Execute(os.Stdout, map[string]string{"Name": "                 
                      <script>alert('Can you see me?')</script>"})
                if err != nil {
                        return err
                }

                // you can also manually call the escapers
                fmt.Println(template.JSEscaper(`example         
                <example@example.com>`))
                fmt.Println(template.HTMLEscaper(`example 
                <example@example.com>`))
                fmt.Println(template.URLQueryEscaper(`example 
                <example@example.com>`))

                return nil
        }
```

1.  创建一个名为`example`的新目录并进入其中。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter1/templates"

        func main() {
                if err := templates.RunTemplate(); err != nil {
                        panic(err)
                }

                if err := templates.InitTemplates(); err != nil {
                        panic(err)
                }

                if err := templates.HTMLDifferences(); err != nil {
                        panic(err)
                }
        }
```

1.  运行`go run .`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该会看到以下输出（路径不同）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-cb-2e/img/ef2b6984-de94-468d-b65b-f6d33afaa564.png)

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 工作原理...

Go 有两个模板包：`text/template`和`html/template`。它们共享功能和各种函数。一般来说，您应该使用`html/template`来渲染网站，而`text/template`用于其他所有内容。模板是纯文本，但变量和函数可以在花括号块内使用。

模板包还提供了方便的方法来处理文件。我们在这里使用的示例在临时目录中创建了许多模板，然后用一行代码读取了它们。

`html/template`包是`text/template`包的包装器。所有的模板示例都直接使用`html/template`包，不做任何修改，只改变导入语句。HTML 模板提供了上下文感知的安全性，这可以防止诸如 JavaScript 注入之类的安全漏洞。

模板包提供了现代模板库应有的功能。很容易组合模板，添加应用程序逻辑，并确保在将结果输出到 HTML 和 JavaScript 时的安全性。


# 第二章：命令行工具

命令行应用程序是处理用户输入和输出的最简单方式之一。本章将重点介绍基于命令行的交互，如命令行参数、配置和环境变量。最后，我们将介绍一个用于在 Unix 和 Bash for Windows 中着色文本输出的库。

通过本章的配方，您应该能够处理预期和意外的用户输入。*捕获和处理信号*配方是一个例子，说明用户可能向您的应用程序发送意外信号的情况，而管道配方是相对于标志或命令行参数来说获取用户输入的一个很好的替代方法。

ANSI 颜色配方有望提供一些清理输出给用户的示例。例如，在日志记录中，能够根据其用途着色文本有时可以使大块文本变得更清晰。

在本章中，我们将介绍以下配方：

+   使用命令行标志

+   使用命令行参数

+   读取和设置环境变量

+   使用 TOML、YAML 和 JSON 进行配置

+   使用 Unix 管道

+   捕获和处理信号

+   一个 ANSI 着色应用程序

# 技术要求

为了继续本章中的所有配方，请根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开终端或控制台应用程序，并创建并导航到项目目录，例如`~/projects/go-programming-cookbook`。我们所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，并从该目录中工作，而不是手动输入示例： 

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 使用命令行标志

`flag`包使得向 Go 应用程序添加命令行标志参数变得简单。它有一些缺点——您往往需要重复大量的代码来添加标志的简写版本，并且它们按照帮助提示的字母顺序排列。有许多第三方库试图解决这些缺点，但本章将重点介绍标准库版本，而不是这些库。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter2/flags`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/flags 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/flags    
```

1.  从`~/projects/go-programming-cookbook-original/chapter2/flags`复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`flags.go`的文件，内容如下：

```go
        package main

        import (
             "flag"
             "fmt"
        )

        // Config will be the holder for our flags
        type Config struct {
             subject string
             isAwesome bool
             howAwesome int
             countTheWays CountTheWays
        }

        // Setup initializes a config from flags that
        // are passed in
        func (c *Config) Setup() {
            // you can set a flag directly like so:
            // var someVar = flag.String("flag_name", "default_val",           
            // "description")
            // but in practice putting it in a struct is generally 
            // better longhand
            flag.StringVar(&c.subject, "subject", "", "subject is a           
            string, it defaults to empty")
            // shorthand
            flag.StringVar(&c.subject, "s", "", "subject is a string, 
            it defaults to empty (shorthand)")

           flag.BoolVar(&c.isAwesome, "isawesome", false, "is it 
           awesome or what?")
           flag.IntVar(&c.howAwesome, "howawesome", 10, "how awesome 
           out of 10?")

           // custom variable type
           flag.Var(&c.countTheWays, "c", "comma separated list of 
           integers")
        }

        // GetMessage uses all of the internal
        // config vars and returns a sentence
        func (c *Config) GetMessage() string {
            msg := c.subject
            if c.isAwesome {
                msg += " is awesome"
            } else {
                msg += " is NOT awesome"
            }

            msg = fmt.Sprintf("%s with a certainty of %d out of 10\. Let 
            me count the ways %s", msg, c.howAwesome, 
            c.countTheWays.String())
            return msg
        }
```

1.  创建一个名为`custom.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "strconv"
            "strings"
        )

        // CountTheWays is a custom type that
        // we'll read a flag into
        type CountTheWays []int

        func (c *CountTheWays) String() string {
            result := ""
            for _, v := range *c {
                if len(result) > 0 {
                    result += " ... "
                }
                result += fmt.Sprint(v)
            }
            return result
        }

        // Set will be used by the flag package
        func (c *CountTheWays) Set(value string) error {
            values := strings.Split(value, ",")

            for _, v := range values {
                i, err := strconv.Atoi(v)
                if err != nil {
                    return err
                }
                *c = append(*c, i)
            }

            return nil
        }
```

1.  运行以下命令：

```go
$ go mod tidy
```

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "flag"
            "fmt"
        )

        func main() {
            // initialize our setup
            c := Config{}
            c.Setup()

            // generally call this from main
            flag.Parse()

            fmt.Println(c.GetMessage())
        }
```

1.  在命令行上运行以下命令：

```go
$ go build $ ./flags -h
```

1.  尝试这些和其他一些参数；您应该看到以下输出：

```go
$ go build 
$ ./flags -h 
Usage of ./flags:
-c value
comma separated list of integers
-howawesome int
how awesome out of 10? (default 10)
-isawesome
is it awesome or what? (default false)
-s string
subject is a string, it defaults to empty (shorthand)
-subject string
subject is a string, it defaults to empty
$ ./flags -s Go -isawesome -howawesome 10 -c 1,2,3 
Go is awesome with a certainty of 10 out of 10\. Let me count 
the ways 1 ... 2 ... 3
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`，确保所有测试都通过。

# 它是如何工作的...

该配方试图演示`flag`包的大多数常见用法。它显示自定义变量类型、各种内置变量、简写标志，并将所有标志写入一个公共结构。这是第一个需要主函数的配方，因为应该从主函数中调用 flag 的主要用法（`flag.Parse()`）。因此，正常的示例目录被省略了。

该应用程序的示例用法显示，您会自动得到`-h`以获取包含的标志列表。还有一些需要注意的是，布尔标志是在没有参数的情况下调用的，而标志的顺序并不重要。

`flag`包是一种快速构建命令行应用程序输入的方式，并提供了一种灵活的方式来指定用户输入，比如设置日志级别或应用程序的冗长程度。在*使用命令行参数*示例中，我们将探讨标志集并使用参数在它们之间切换。

# 使用命令行参数

上一个示例中的标志是一种命令行参数。本章将扩展这些参数的其他用途，通过构建支持嵌套子命令的命令来演示标志集，并使用传递给应用程序的位置参数。

与上一个示例一样，这个示例需要一个主函数来运行。有许多第三方包处理复杂的嵌套参数和标志，但我们将探讨如何仅使用标准库来实现这一点。

# 如何操作...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter2/cmdargs`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/cmdargs 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/cmdargs   
```

1.  从`~/projects/go-programming-cookbook-original/chapter2/cmdargs`中复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`cmdargs.go`的文件，内容如下：

```go
        package main
        import (
            "flag"
            "fmt"
            "os"
        )
        const version = "1.0.0"
        const usage = `Usage:
        %s [command]
        Commands:
            Greet
            Version
        `
        const greetUsage = `Usage:
        %s greet name [flag]
        Positional Arguments:
            name
                the name to greet
        Flags:
        `
        // MenuConf holds all the levels
        // for a nested cmd line argument
        type MenuConf struct {
            Goodbye bool
        }
        // SetupMenu initializes the base flags
        func (m *MenuConf) SetupMenu() *flag.FlagSet {
            menu := flag.NewFlagSet("menu", flag.ExitOnError)
            menu.Usage = func() {
                fmt.Printf(usage, os.Args[0])
                menu.PrintDefaults()
            }
            return menu
        }
        // GetSubMenu return a flag set for a submenu
        func (m *MenuConf) GetSubMenu() *flag.FlagSet {
            submenu := flag.NewFlagSet("submenu", flag.ExitOnError)
            submenu.BoolVar(&m.Goodbye, "goodbye", false, "Say goodbye 
            instead of hello")
            submenu.Usage = func() {
                fmt.Printf(greetUsage, os.Args[0])
                submenu.PrintDefaults()
            }
            return submenu
        }
        // Greet will be invoked by the greet command
        func (m *MenuConf) Greet(name string) {
            if m.Goodbye {
                fmt.Println("Goodbye " + name + "!")
            } else {
                fmt.Println("Hello " + name + "!")
            }
        }
        // Version prints the current version that is
        // stored as a const
        func (m *MenuConf) Version() {
            fmt.Println("Version: " + version)
        }
```

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "os"
  "strings"
)

func main() {
  c := MenuConf{}
  menu := c.SetupMenu()

  if err := menu.Parse(os.Args[1:]); err != nil {
    fmt.Printf("Error parsing params %s, error: %v", os.Args[1:], err)
    return
  }

  // we use arguments to switch between commands
  // flags are also an argument
  if len(os.Args) > 1 {
    // we don't care about case
    switch strings.ToLower(os.Args[1]) {
    case "version":
      c.Version()
    case "greet":
      f := c.GetSubMenu()
      if len(os.Args) < 3 {
        f.Usage()
        return
      }
      if len(os.Args) > 3 {
        if err := f.Parse(os.Args[3:]); err != nil {
          fmt.Fprintf(os.Stderr, "Error parsing params %s, error: %v", os.Args[3:], err)
          return
        }

      }
      c.Greet(os.Args[2])

    default:
      fmt.Println("Invalid command")
      menu.Usage()
      return
    }
  } else {
    menu.Usage()
    return
  }
}
```

1.  运行`go build`。

1.  运行以下命令，并尝试一些其他参数的组合：

```go
$ ./cmdargs -h 
Usage:

./cmdargs [command]

Commands:
Greet
Version

$./cmdargs version
Version: 1.0.0

$./cmdargs greet
Usage:

./cmdargs greet name [flag]

Positional Arguments:
 name
 the name to greet

Flags:
 -goodbye
 Say goodbye instead of hello

$./cmdargs greet reader
Hello reader!

$./cmdargs greet reader -goodbye
Goodbye reader!
```

1.  如果你复制或编写了自己的测试，返回上一级目录并运行`go test`，确保所有测试都通过。

# 它是如何工作的...

标志集可用于设置独立的预期参数列表、使用字符串等。开发人员需要对许多参数进行验证，将正确的子集参数解析到命令中，并定义使用字符串。这可能容易出错，并需要大量迭代才能完全正确。

`flag`包使解析参数变得更加容易，并包括方便的方法来获取标志的数量、参数等。这个示例演示了使用参数构建复杂命令行应用程序的基本方法，包括包级配置、必需的位置参数、多级命令使用，以及如何将这些内容拆分成多个文件或包（如果需要）。

# 读取和设置环境变量

环境变量是另一种可以将状态传递到应用程序中的方式，除了从文件中读取数据或通过命令行显式传递数据。这个示例将探讨一些非常基本的获取和设置环境变量的方法，然后使用非常有用的第三方库`envconfig`（[`github.com/kelseyhightower/envconfig`](https://github.com/kelseyhightower/envconfig)）。

我们将构建一个应用程序，可以通过 JSON 或环境变量读取`config`文件。下一个示例将探讨替代格式，包括 TOML 和 YAML。

# 如何操作...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter2/envvar`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/envvar 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/envvar   
```

1.  复制`~/projects/go-programming-cookbook-original/chapter2/envvar`中的测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
        package envvar

        import (
            "encoding/json"
            "os"

            "github.com/kelseyhightower/envconfig"
            "github.com/pkg/errors"
        )

        // LoadConfig will load files optionally from the json file 
        // stored at path, then will override those values based on the 
        // envconfig struct tags. The envPrefix is how we prefix our 
        // environment variables.
        func LoadConfig(path, envPrefix string, config interface{}) 
        error {
            if path != "" {
               err := LoadFile(path, config)
               if err != nil {
                   return errors.Wrap(err, "error loading config from 
                   file")
               }
            }
            err := envconfig.Process(envPrefix, config)
            return errors.Wrap(err, "error loading config from env")
        }

        // LoadFile unmarshalls a json file into a config struct
        func LoadFile(path string, config interface{}) error {
            configFile, err := os.Open(path)
            if err != nil {
                return errors.Wrap(err, "failed to read config file")
         }
         defer configFile.Close()

         decoder := json.NewDecoder(configFile)
         if err = decoder.Decode(config); err != nil {
             return errors.Wrap(err, "failed to decode config file")
         }
         return nil
        }
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "bytes"
            "fmt"
            "io/ioutil"
            "os"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter2/envvar"
        )

        // Config will hold the config we
        // capture from a json file and env vars
        type Config struct {
            Version string `json:"version" required:"true"`
            IsSafe bool `json:"is_safe" default:"true"`
            Secret string `json:"secret"`
        }

        func main() {
            var err error

            // create a temporary file to hold
            // an example json file
            tf, err := ioutil.TempFile("", "tmp")
            if err != nil {
                panic(err)
            }
            defer tf.Close()
            defer os.Remove(tf.Name())

            // create a json file to hold
            // our secrets
            secrets := `{
                "secret": "so so secret"
            }`

            if _, err =   
            tf.Write(bytes.NewBufferString(secrets).Bytes()); 
            err != nil {
                panic(err)
            }

            // We can easily set environment variables
            // as needed
            if err = os.Setenv("EXAMPLE_VERSION", "1.0.0"); err != nil 
            {
                panic(err)
            }
            if err = os.Setenv("EXAMPLE_ISSAFE", "false"); err != nil {
                panic(err)
            }

            c := Config{}
            if err = envvar.LoadConfig(tf.Name(), "EXAMPLE", &c);
            err != nil {
                panic(err)
            }

            fmt.Println("secrets file contains =", secrets)

            // We can also read them
            fmt.Println("EXAMPLE_VERSION =", 
            os.Getenv("EXAMPLE_VERSION"))
            fmt.Println("EXAMPLE_ISSAFE =", 
            os.Getenv("EXAMPLE_ISSAFE"))

            // The final config is a mix of json and environment
            // variables
            fmt.Printf("Final Config: %#v\n", c)
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
go build ./example
```

1.  你应该看到以下输出：

```go
$ go run main.go
secrets file contains = {
"secret": "so so secret"
}
EXAMPLE_VERSION = 1.0.0
EXAMPLE_ISSAFE = false
Final Config: main.Config{Version:"1.0.0", IsSafe:false, 
Secret:"so so secret"}
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶级示例目录中。

1.  如果你复制或编写了自己的测试，返回上一级目录并运行`go test`，确保所有测试都通过。

# 它是如何工作的...

使用`os`包读取和写入环境变量非常简单。这个配方使用的`envconfig`第三方库是一种聪明的方式，可以捕获环境变量并使用`struct`标签指定某些要求。

`LoadConfig`函数是一种灵活的方式，可以从各种来源获取配置信息，而不需要太多的开销或太多额外的依赖。将主要的`config`转换为除 JSON 以外的其他格式，或者始终使用环境变量也很简单。

还要注意错误的使用。我们在这个配方的代码中包装了错误，这样我们就可以注释错误而不会丢失原始错误的信息。在第四章中会有更多关于这个的细节，*Go 中的错误处理*。

# 使用 TOML、YAML 和 JSON 进行配置

Go 有许多配置格式，通过使用第三方库，支持。其中三种最流行的数据格式是 TOML、YAML 和 JSON。Go 可以直接支持 JSON，其他格式有关于如何为这些格式编组/解组或编码/解码数据的线索。这些格式除了配置之外还有许多好处，但本章主要关注将 Go 结构转换为配置结构的过程。这个配方将探讨使用这些格式进行基本输入和输出。

这些格式还提供了一个接口，通过这个接口，Go 和其他语言编写的应用程序可以共享相同的配置。还有许多处理这些格式并简化与它们一起工作的工具。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter2/confformat`的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/confformat 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/confformat   
```

1.  从`~/projects/go-programming-cookbook-original/chapter2/confformat`复制测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`toml.go`的文件，内容如下：

```go
        package confformat

        import (
            "bytes"

            "github.com/BurntSushi/toml"
        )

        // TOMLData is our common data struct
        // with TOML struct tags
        type TOMLData struct {
            Name string `toml:"name"`
            Age int `toml:"age"`
        }

        // ToTOML dumps the TOMLData struct to
        // a TOML format bytes.Buffer
        func (t *TOMLData) ToTOML() (*bytes.Buffer, error) {
            b := &bytes.Buffer{}
            encoder := toml.NewEncoder(b)

            if err := encoder.Encode(t); err != nil {
                return nil, err
            }
            return b, nil
        }

        // Decode will decode into TOMLData
        func (t *TOMLData) Decode(data []byte) (toml.MetaData, error) {
            return toml.Decode(string(data), t)
        }
```

1.  创建一个名为`yaml.go`的文件，内容如下：

```go
        package confformat

        import (
            "bytes"

            "github.com/go-yaml/yaml"
        )

        // YAMLData is our common data struct
        // with YAML struct tags
        type YAMLData struct {
            Name string `yaml:"name"`
            Age int `yaml:"age"`
        }

        // ToYAML dumps the YAMLData struct to
        // a YAML format bytes.Buffer
        func (t *YAMLData) ToYAML() (*bytes.Buffer, error) {
            d, err := yaml.Marshal(t)
            if err != nil {
                return nil, err
            }

            b := bytes.NewBuffer(d)

            return b, nil
        }

        // Decode will decode into TOMLData
        func (t *YAMLData) Decode(data []byte) error {
            return yaml.Unmarshal(data, t)
        }
```

1.  创建一个名为`json.go`的文件，内容如下：

```go
        package confformat

        import (
            "bytes"
            "encoding/json"
            "fmt"
        )

        // JSONData is our common data struct
        // with JSON struct tags
        type JSONData struct {
            Name string `json:"name"`
            Age int `json:"age"`
        }

        // ToJSON dumps the JSONData struct to
        // a JSON format bytes.Buffer
        func (t *JSONData) ToJSON() (*bytes.Buffer, error) {
            d, err := json.Marshal(t)
            if err != nil {
                return nil, err
            }

            b := bytes.NewBuffer(d)

            return b, nil
        }

        // Decode will decode into JSONData
        func (t *JSONData) Decode(data []byte) error {
            return json.Unmarshal(data, t)
        }

        // OtherJSONExamples shows ways to use types
        // beyond structs and other useful functions
        func OtherJSONExamples() error {
            res := make(map[string]string)
            err := json.Unmarshal([]byte(`{"key": "value"}`), &res)
            if err != nil {
                return err
            }

            fmt.Println("We can unmarshal into a map instead of a 
            struct:", res)

            b := bytes.NewReader([]byte(`{"key2": "value2"}`))
            decoder := json.NewDecoder(b)

            if err := decoder.Decode(&res); err != nil {
                return err
            }

            fmt.Println("we can also use decoders/encoders to work with 
            streams:", res)

            return nil
        }
```

1.  创建一个名为`marshal.go`的文件，内容如下：

```go
        package confformat

        import "fmt"

        // MarshalAll takes some data stored in structs
        // and converts them to the various data formats
        func MarshalAll() error {
            t := TOMLData{
                Name: "Name1",
                Age: 20,
            }

            j := JSONData{
                Name: "Name2",
                Age: 30,
            }

            y := YAMLData{
                Name: "Name3",
                Age: 40,
            }

            tomlRes, err := t.ToTOML()
            if err != nil {
                return err
            }

            fmt.Println("TOML Marshal =", tomlRes.String())

            jsonRes, err := j.ToJSON()
            if err != nil {
                return err
            }

            fmt.Println("JSON Marshal=", jsonRes.String())

            yamlRes, err := y.ToYAML()
            if err != nil {
                return err
            }

            fmt.Println("YAML Marshal =", yamlRes.String())
                return nil
        }
```

1.  创建一个名为`unmarshal.go`的文件，内容如下：

```go
        package confformat
        import "fmt"
        const (
            exampleTOML = `name="Example1"
        age=99
            `
            exampleJSON = `{"name":"Example2","age":98}`
            exampleYAML = `name: Example3
        age: 97 
            `
        )
        // UnmarshalAll takes data in various formats
        // and converts them into structs
        func UnmarshalAll() error {
            t := TOMLData{}
            j := JSONData{}
            y := YAMLData{}
            if _, err := t.Decode([]byte(exampleTOML)); err != nil {
                return err
            }
            fmt.Println("TOML Unmarshal =", t)

            if err := j.Decode([]byte(exampleJSON)); err != nil {
                return err
            }
            fmt.Println("JSON Unmarshal =", j)

            if err := y.Decode([]byte(exampleYAML)); err != nil {
                return err
            }
            fmt.Println("Yaml Unmarshal =", y)
                return nil
            }
```

1.  创建一个名为`example`的新目录并导航到该目录。

1.  创建一个`main.go`文件，内容如下：

```go
        package main

        import "github.com/PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                chapter2/confformat"

        func main() {
            if err := confformat.MarshalAll(); err != nil {
                panic(err)
            }

            if err := confformat.UnmarshalAll(); err != nil {
                panic(err)
            }

            if err := confformat.OtherJSONExamples(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

1.  你应该看到以下输出：

```go
$ go run main.go
TOML Marshal = name = "Name1"
age = 20

JSON Marshal= {"name":"Name2","age":30}
YAML Marshal = name: Name3
age: 40

TOML Unmarshal = {Example1 99}
JSON Unmarshal = {Example2 98}
Yaml Unmarshal = {Example3 97}
We can unmarshal into a map instead of a struct: map[key:value]
we can also use decoders/encoders to work with streams: 
map[key:value key2:value2]
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶级配方目录中。

1.  如果你复制或编写了自己的测试，返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这个配方为我们提供了如何使用 TOML、YAML 和 JSON 解析器的示例，用于将原始数据写入 go 结构并从中读取数据并转换为相应的格式。就像第一章中的配方，*I/O 和文件系统*，我们看到了在`[]byte`、`string`、`bytes.Buffer`和其他 I/O 接口之间快速切换是多么常见。

`encoding/json`包在提供编码、编组和其他方法以处理 JSON 格式方面是最全面的。我们通过`ToFormat`函数将这些抽象出来，非常简单地可以附加多个类似的方法，这样我们就可以使用一个结构快速地转换成任何这些类型，或者从这些类型转换出来。

这个配方还涉及结构标签及其用法。上一章也使用了这些，它们是一种常见的方式，用于向包和库提供关于如何处理结构中包含的数据的提示。

# 使用 Unix 管道进行工作

当我们将一个程序的输出传递给另一个程序的输入时，Unix 管道非常有用。例如，看一下以下代码：

```go
$ echo "test case" | wc -l
 1
```

在 Go 应用程序中，管道的左侧可以使用`os.Stdin`进行读取，它的作用类似于文件描述符。为了演示这一点，本教程将接受管道左侧的输入，并返回一个单词列表及其出现次数。这些单词将在空格上进行标记化。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter2/pipes`的新目录。

1.  导航到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/pipes
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/pipes   
```

1.  从`~/projects/go-programming-cookbook-original/chapter2/pipes`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`pipes.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "bufio"
            "fmt"
            "io"
            "os"
        )

        // WordCount takes a file and returns a map
        // with each word as a key and it's number of
        // appearances as a value
        func WordCount(f io.Reader) map[string]int {
            result := make(map[string]int)

            // make a scanner to work on the file
            // io.Reader interface
            scanner := bufio.NewScanner(f)
            scanner.Split(bufio.ScanWords)

            for scanner.Scan() {
                result[scanner.Text()]++
            }

            if err := scanner.Err(); err != nil {
                fmt.Fprintln(os.Stderr, "reading input:", err)
            }

            return result
        }

        func main() {
            fmt.Printf("string: number_of_occurrences\n\n")
            for key, value := range WordCount(os.Stdin) {
                fmt.Printf("%s: %d\n", key, value)
            }
        }
```

1.  运行`echo "some string" | go run pipes.go`。

1.  您还可以运行以下命令：

```go
$ go build echo "some string" | ./pipes
```

您应该会看到以下输出：

```go
$ echo "test case" | go run pipes.go
string: number_of_occurrences

test: 1
case: 1

$ echo "test case test" | go run pipes.go
string: number_of_occurrences

test: 2
case: 1
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

在 Go 中使用管道非常简单，特别是如果您熟悉使用文件。例如，您可以使用第一章中的管道教程，*I/O 和文件系统*，创建一个**tee**应用程序（[`en.wikipedia.org/wiki/Tee_(command)`](https://en.wikipedia.org/wiki/Tee_(command)）其中所有输入的内容都立即写入到`stdout`和文件中。

本教程使用扫描程序来标记`os.Stdin`文件对象的`io.Reader`接口。您可以看到在完成所有读取后必须检查错误。

# 捕获和处理信号

信号是用户或操作系统终止正在运行的应用程序的有用方式。有时，以比默认行为更优雅的方式处理这些信号是有意义的。Go 提供了一种机制来捕获和处理信号。在本教程中，我们将通过使用处理 Go 例程的信号来探讨信号的处理。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter2/signals`的新目录。

1.  导航到此目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/signals 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/signals   
```

1.  从`~/projects/go-programming-cookbook-original/chapter2/signals`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`signals.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"
            "os"
            "os/signal"
            "syscall"
        )

        // CatchSig sets up a listener for
        // SIGINT interrupts
        func CatchSig(ch chan os.Signal, done chan bool) {
            // block on waiting for a signal
            sig := <-ch
            // print it when it's received
            fmt.Println("nsig received:", sig)

            // we can set up handlers for all types of
            // sigs here
            switch sig {
            case syscall.SIGINT:
                fmt.Println("handling a SIGINT now!")
            case syscall.SIGTERM:
                fmt.Println("handling a SIGTERM in an entirely 
                different way!")
            default:
                fmt.Println("unexpected signal received")
            }

            // terminate
            done <- true
        }

        func main() {
            // initialize our channels
            signals := make(chan os.Signal)
            done := make(chan bool)

            // hook them up to the signals lib
            signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

            // if a signal is caught by this go routine
            // it will write to done
            go CatchSig(signals, done)

            fmt.Println("Press ctrl-c to terminate...")
            // the program blocks until someone writes to done
            <-done
            fmt.Println("Done!")

        }
```

1.  运行以下命令：

```go
$ go build $ ./signals
```

1.  尝试运行代码，然后按*Ctrl* + *C*。您应该会看到以下内容：

```go
$./signals
Press ctrl-c to terminate...
^C
sig received: interrupt
handling a SIGINT now!
Done!
```

1.  尝试再次运行它。然后，从另一个终端确定 PID 并终止应用程序：

```go
$./signals
Press ctrl-c to terminate...

# in a separate terminal
$ ps -ef | grep signals
501 30777 26360 0 5:00PM ttys000 0:00.00 ./signals

$ kill -SIGTERM 30777

# in the original terminal

sig received: terminated
handling a SIGTERM in an entirely different way!
Done!
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

本教程使用了通道，这在第九章“并行和并发”中有更详细的介绍。`signal.Notify`函数需要一个通道来发送信号通知，还需要我们关心的信号类型。然后，我们在 Go 例程中设置一个函数来处理我们传递给该函数的通道上的任何活动。一旦我们收到信号，我们可以以任何我们想要的方式处理它。我们可以终止应用程序，回复消息，并对不同的信号有不同的行为。`kill`命令是测试向应用程序传递信号的好方法。

我们还使用一个 `done` 通道来阻止应用程序在接收到信号之前终止。否则，程序会立即终止。对于长时间运行的应用程序（如 Web 应用程序），这是不必要的。创建适当的信号处理例程来执行清理工作可能非常有用，特别是在具有大量 Go 协程并持有大量状态的应用程序中。一个优雅关闭的实际例子可能是允许当前处理程序完成其 HTTP 请求而不会在中途终止它们。

# 一个 ANSI 着色应用程序

对 ANSI 终端应用程序进行着色是通过一系列代码来处理的，在你想要着色的文本之前和之后。本教程将探讨一种基本的着色机制，可以将文本着色为红色或普通色。要了解完整的应用程序，请查看 [`github.com/agtorre/gocolorize`](https://github.com/agtorre/gocolorize)，它支持更多的颜色和文本类型，并且还实现了 `fmt.Formatter` 接口以便于打印。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为 `~/projects/go-programming-cookbook/chapter2/ansicolor` 的新目录。

1.  导航到这个目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/ansicolor 
```

您应该会看到一个名为 `go.mod` 的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter2/ansicolor   
```

1.  从 `~/projects/go-programming-cookbook-original/chapter2/ansicolor` 复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为 `color.go` 的文件，其中包含以下内容：

```go
        package ansicolor

        import "fmt"

        //Color of text
        type Color int

        const (
            // ColorNone is default
            ColorNone = iota
            // Red colored text
            Red
            // Green colored text
            Green
            // Yellow colored text
            Yellow
            // Blue colored text
            Blue
            // Magenta colored text
            Magenta
            // Cyan colored text
            Cyan
            // White colored text
            White
            // Black colored text
            Black Color = -1
        )

        // ColorText holds a string and its color
        type ColorText struct {
            TextColor Color
            Text      string
        }

        func (r *ColorText) String() string {
            if r.TextColor == ColorNone {
                return r.Text
            }

            value := 30
            if r.TextColor != Black {
                value += int(r.TextColor)
            }
            return fmt.Sprintf("33[0;%dm%s33[0m", value, r.Text)
        }
```

1.  创建一个名为 `example` 的新目录并导航到它。

1.  创建一个名为 `main.go` 的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter2/ansicolor"
        )

        func main() {
            r := ansicolor.ColorText{
                TextColor: ansicolor.Red,
                Text:      "I'm red!",
            }

            fmt.Println(r.String())

            r.TextColor = ansicolor.Green
            r.Text = "Now I'm green!"

            fmt.Println(r.String())

            r.TextColor = ansicolor.ColorNone
            r.Text = "Back to normal..."

            fmt.Println(r.String())
        }
```

1.  运行 `go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

1.  如果您的终端支持 ANSI 着色格式，您应该会看到以下输出的文本被着色：

```go
$ go run main.go
I'm red!
Now I'm green!
Back to normal...
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行 `go test`。确保所有测试都通过。

# 工作原理...

该应用程序利用一个结构来维护着色文本的状态。在这种情况下，它存储文本的颜色和值。当您调用 `String()` 方法时，最终的字符串将被渲染，根据结构中存储的值，它将返回着色文本或普通文本。默认情况下，文本将是普通的。
