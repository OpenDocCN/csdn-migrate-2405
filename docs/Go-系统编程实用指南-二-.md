# Go 系统编程实用指南（二）

> 原文：[`zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA`](https://zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：处理流

本章涉及数据流，将输入和输出接口扩展到文件系统之外，并介绍如何实现自定义读取器和写入器以满足任何目的。

它还专注于输入和输出实用程序的缺失部分，以多种不同的方式将它们组合在一起，目标是完全控制传入和传出的数据。

本章将涵盖以下主题：

+   流

+   自定义读取器

+   自定义写入器

+   实用程序

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅第三章，*Go 概述*。

# 流

写入器和读取器不仅仅用于文件；它们是抽象数据流的接口，这些流通常被称为**流**，是大多数应用程序的重要组成部分。

# 输入和读取器

如果应用程序无法控制数据流，并且将等待错误来结束流程，则传入的数据流被视为`io.Reader`接口，在最佳情况下会收到`io.EOF`值，这是一个特殊的错误，表示没有更多内容可读取，否则会收到其他错误。另一种选择是读取器也能够终止流。在这种情况下，正确的表示是`io.ReadCloser`接口。

除了`os.File`，标准包中还有几个读取器的实现。

# 字节读取器

`bytes`包含一个有用的结构，它将字节切片视为`io.Reader`接口，并实现了许多更多的 I/O 接口：

+   `io.Reader`：这可以作为常规读取器

+   `io.ReaderAt`：这使得可以从特定位置开始读取

+   `io.WriterTo`：这使得可以在偏移量处写入内容

+   `io.Seeker`：这可以自由移动读取器的光标

+   `io.ByteScanner`：这可以为每个字节执行读取操作

+   `io.RuneScanner`：这可以对由多个字节组成的字符执行相同的操作

符文和字节之间的区别可以通过以下示例来澄清，其中我们有一个由一个符文组成的字符串`⌘`，它由三个字节`e28c98`表示：

```go
func main() {
    const a = `⌘`

    fmt.Printf("plain string: %s\n", a)
    fmt.Printf("quoted string: %q\n",a)

    fmt.Printf("hex bytes: ")
    for i := 0; i < len(a); i++ {
        fmt.Printf("%x ", a[i])
    }
    fmt.Printf("\n")
}
```

完整的示例可在[`play.golang.org/p/gVZOufSmlq1`](https://play.golang.org/p/gVZOufSmlq1)找到。

还有`bytes.Buffer`，它在`bytes.Reader`的基础上添加了写入功能，并且可以访问底层切片或将内容作为字符串获取。

`Buffer.String`方法将字节转换为字符串，在 Go 中进行此类转换是通过复制字节来完成的，因为字符串是不可变的。这意味着对缓冲区的任何更改都将在复制后进行，不会传播到字符串。

# 字符串读取器

`strings`包含另一个与`io.Reader`接口非常相似的结构，称为`strings.Reader`。它的工作方式与第一个完全相同，但底层值是字符串而不是字节切片。

在处理需要读取的字符串时，使用字符串而不是字节读取器的主要优势之一是避免在初始化时复制数据。这种微妙的差异有助于提高性能和内存使用，因为它减少了分配并需要**垃圾回收器**（**GC**）清理副本。

# 定义读取器

任何 Go 应用程序都可以定义`io.Reader`接口的自定义实现。在实现接口时的一个很好的一般规则是接受接口并返回具体类型，避免不必要的抽象。

让我们看一个实际的例子。我们想要实现一个自定义读取器，它从另一个读取器中获取内容并将其转换为大写；例如，我们可以称之为`AngryReader`：

```go
func NewAngryReader(r io.Reader) *AngryReader {
    return &AngryReader{r: r}
}

type AngryReader struct {
    r io.Reader
}

func (a *AngryReader) Read(b []byte) (int, error) {
    n, err := a.r.Read(b)
    for r, i, w := rune(0), 0, 0; i < n; i += w {
        // read a rune
        r, w = utf8.DecodeRune(b[i:])
        // skip if not a letter
        if !unicode.IsLetter(r) {
            continue
        }
        // uppercase version of the rune
        ru := unicode.ToUpper(r)
        // encode the rune and expect same length
        if wu := utf8.EncodeRune(b[i:], ru); w != wu {
            return n, fmt.Errorf("%c->%c, size mismatch %d->%d", r, ru, w, wu)
        }
    }
    return n, err
}
```

这是一个非常直接的例子，使用`unicode`和`unicode/utf8`来实现其目标：

+   `utf8.DecodeRune`用于获取第一个符文及其宽度是读取的切片的一部分

+   `unicode.IsLetter`确定符文是否为字母

+   `unicode.ToUpper`将文本转换为大写

+   `ut8.EncodeLetter`将新字母写入必要的字节

+   字母及其大写版本应该具有相同的宽度

完整示例可在[`play.golang.org/p/PhdSsbzXcbE`](https://play.golang.org/p/PhdSsbzXcbE)找到。

# 输出和写入器

适用于传入流的推理也适用于传出流。我们有`io.Writer`接口，应用程序只能发送数据，还有`io.WriteCloser`接口，它还能关闭连接。

# 字节写入器

我们已经看到`bytes`包提供了`Buffer`，它具有读取和写入功能。这实现了`ByteReader`接口的所有方法，以及一个以上的`Writer`接口：

+   `io.Writer`：这可以作为常规写入器

+   `io.WriterAt`：这使得可以从某个位置开始写入

+   io.ByteWriter：这使得可以写入单个字节

`bytes.Buffer`是一个非常灵活的结构，因为它既适用于`Writer`和`ByteWriter`，如果重复使用，它的`Reset`和`Truncate`方法效果最佳。与其让 GC 回收已使用的缓冲区并创建一个新的缓冲区，不如重置现有的缓冲区，保留缓冲区的底层数组，并将切片长度设置为`0`。

在前一章中，我们看到了缓冲区使用的一个很好的例子：

```go
    bookList := []book{
        {Author: grr, Title: "A Game of Thrones", Year: 1996},
        {Author: grr, Title: "A Clash of Kings", Year: 1998},
        {Author: grr, Title: "A Storm of Swords", Year: 2000},
        {Author: grr, Title: "A Feast for Crows", Year: 2005},
        {Author: grr, Title: "A Dance with Dragons", Year: 2011},
        {Author: grr, Title: "The Winds of Winter"},
        {Author: grr, Title: "A Dream of Spring"},
    }
    b := bytes.NewBuffer(make([]byte, 0, 16))
    for _, v := range bookList {
        // prints a msg formatted with arguments to writer
        fmt.Fprintf(b, "%s - %s", v.Title, v.Author)
        if v.Year > 0 { // we do not print the year if it's not there
            fmt.Fprintf(b, " (%d)", v.Year)
        }
        b.WriteRune('\n')
        if _, err := b.WriteTo(dst); true { // copies bytes, drains buffer
            fmt.Println("Error:", err)
            return
        }
    }
```

缓冲区不适用于组合字符串值。因此，当调用`String`方法时，字节会被转换为不可变的字符串，与切片不同。以这种方式创建的新字符串是使用当前切片的副本制作的，对切片的更改不会影响字符串。这既不是限制也不是特性；这是一个属性，如果使用不正确可能会导致错误。以下是重置缓冲区并使用`String`方法的效果示例：

```go
package main

import (
    "bytes"
    "fmt"
)

func main() {
    b := bytes.NewBuffer(nil)
    b.WriteString("One")
    s1 := b.String()
    b.WriteString("Two")
    s2 := b.String()
    b.Reset()
    b.WriteString("Hey!")    // does not change s1 or s2
    s3 := b.String()
    fmt.Println(s1, s2, s3)  // prints "One OneTwo Hey!"
}
```

完整示例可在[`play.golang.org/p/zBjGPMC4sfF`](https://play.golang.org/p/zBjGPMC4sfF)找到

# 字符串写入器

字节缓冲区执行字节的复制以生成一个字符串。这就是为什么在 1.10 版本中，`strings.Builder`首次亮相。它共享缓冲区的所有与写入相关的方法，并且不允许通过`Bytes`方法访问底层切片。获取最终字符串的唯一方法是使用`String`方法，它在底层使用`unsafe`包将切片转换为字符串而不复制底层数据。

这样做的主要后果是这个结构强烈地不鼓励复制——因为复制的切片的底层数组指向相同的数组，并且在副本中写入会影响另一个。结果的操作会导致恐慌：

```go
package main

import (
    "strings"
)

func main() {
    b := strings.Builder{}
    b.WriteString("One")
    c := b
    c.WriteString("Hey!") // panic: strings: illegal use of non-zero Builder copied by value
}
```

# 定义一个写入器

任何写入器的自定义实现都可以在应用程序中定义。一个非常常见的情况是装饰器，它是一个包装另一个写入器并改变或扩展原始写入器功能的写入器。至于读取器，最好有一个接受另一个写入器并可能包装它以使其与许多标准库结构兼容的构造函数，例如以下内容：

+   `*os.File`

+   `*bytes.Buffer`

+   `*strings.Builder`

让我们来看一个真实的用例——我们想要生成一些带有每个单词中混淆字母的文本，以测试何时开始变得无法阅读。我们将创建一个可配置的写入器，在将其写入目标写入器之前混淆字母，并创建一个接受文件并创建其混淆版本的二进制文件。我们将使用`math/rand`包来随机化混淆。

让我们定义我们的结构及其构造函数。这将接受另一个写入器、一个随机数生成器和一个混淆的`chance`：

```go
func NewScrambleWriter(w io.Writer, r *rand.Rand, chance float64) *ScrambleWriter {
    return &ScrambleWriter{w: w, r: r, c: chance}
}

type ScrambleWriter struct {
    w io.Writer
    r *rand.Rand
    c float64
}
```

`Write`方法需要执行字节而不是字母，并打乱字母的顺序。它将迭代符文，使用我们之前看到的`ut8.DecodeRune`函数，打印出任何不是字母的内容，并堆叠它可以找到的所有字母序列：

```go
func (s *ScrambleWriter) Write(b []byte) (n int, err error) {
    var runes = make([]rune, 0, 10)
    for r, i, w := rune(0), 0, 0; i < len(b); i += w {
        r, w = utf8.DecodeRune(b[i:])
        if unicode.IsLetter(r) {
            runes = append(runes, r)
            continue
        }
        v, err := s.shambleWrite(runes, r)
        if err != nil {
            return n, err
        }
        n += v
        runes = runes[:0]
    }
    if len(runes) != 0 {
        v, err := s.shambleWrite(runes, 0)
        if err != nil {
            return n, err
        }
        n += v
    }
    return
}
```

当序列结束时，它将由`shambleWrite`方法处理，该方法将有效地执行一个混乱并写入混乱的符文：

```go
func (s *ScrambleWriter) shambleWrite(runes []rune, sep rune) (n int, err error) {
    //scramble after first letter
    for i := 1; i < len(runes)-1; i++ {
        if s.r.Float64() > s.c {
            continue
        }
        j := s.r.Intn(len(runes)-1) + 1
        runes[i], runes[j] = runes[j], runes[i]
    }
    if sep!= 0 {
        runes = append(runes, sep)
    }
    var b = make([]byte, 10)
    for _, r := range runes {
        v, err := s.w.Write(b[:utf8.EncodeRune(b, r)])
        if err != nil {
            return n, err
        }
        n += v
    }
    return
}
```

完整示例可在[`play.golang.org/p/0Xez--6P7nj`](https://play.golang.org/p/0Xez--6P7nj)中找到。

# 内置实用程序

`io`和`io/ioutil`包中有许多其他函数，可以帮助管理读取器、写入器等。了解所有可用的工具将帮助您避免编写不必要的代码，并指导您在使用最佳工具时进行操作。

# 从一个流复制到另一个流

`io`包中有三个主要函数，可以实现从写入器到读取器的数据传输。这是一个非常常见的场景；例如，您可以将从打开的文件中读取的内容写入到另一个打开的文件中，或者将缓冲区中的内容排空并将其内容写入标准输出。

我们已经看到如何在文件上使用`io.Copy`函数来模拟第四章*，与文件系统一起工作*中`cp`命令的行为。这种行为可以扩展到任何读取器和写入器的实现，从缓冲区到网络连接。

如果写入器也是`io.WriterTo`接口，复制将调用`WriteTo`方法。如果不是，它将使用固定大小的缓冲区（32 KB）进行一系列写入。如果操作以`io.EOF`值结束，则不会返回错误。一个常见的情况是`bytes.Buffer`结构，它能够将其内容写入另一个写入器，并且将相应地行事。或者，如果目标是`io.ReaderFrom`接口，则执行`ReadFrom`方法。

如果接口是一个简单的`io.Writer`接口，这个方法将使用一个临时缓冲区，之后将被清除。为了避免在垃圾回收上浪费计算资源，并且可能重用相同的缓冲区，还有另一个函数——`io.CopyBuffer`函数。这有一个额外的参数，只有在这个额外的参数是`nil`时才会分配一个新的缓冲区。

最后一个函数是`io.CopyN`，它的工作原理与`io.Copy`完全相同，但可以指定要写入到额外参数的字节数限制。如果读取器也是`io.Seeker`，则可以有用地写入部分内容——seeker 首先将光标移动到正确的偏移量，然后写入一定数量的字节。

让我们举一个一次复制`n`个字节的例子：

```go
func CopyNOffset(dst io.Writer, src io.ReadSeeker, offset, length int64) (int64, error) {
  if _, err := src.Seek(offset, io.SeekStart); err != nil {
    return 0, err
  }
  return io.CopyN(dst, src, length)
}
```

完整示例可在[`play.golang.org/p/8wCqGXp5mSZ`](https://play.golang.org/p/8wCqGXp5mSZ)中找到。

# 连接的读取器和写入器

`io.Pipe`函数创建一对连接的读取器和写入器。这意味着发送到写入器的任何内容都将从读取器接收到。如果仍有上次操作的挂起数据，写入操作将被阻塞；只有在读取器完成消耗已发送的内容后，新操作才会结束。

这对于非并发应用程序来说并不是一个重要的工具，非并发应用程序更有可能使用通道等并发工具，但是当读取器和写入器在不同的 goroutine 上执行时，这可以是一个很好的同步机制，就像下面的程序一样：

```go
    pr, pw := io.Pipe()
    go func(w io.WriteCloser) {
        for _, s := range []string{"a string", "another string", 
           "last one"} {
                fmt.Printf("-> writing %q\n", s)
                fmt.Fprint(w, s)
        }
        w.Close()
    }(pw)
    var err error
    for n, b := 0, make([]byte, 100); err == nil; {
        fmt.Println("<- waiting...")
        n, err = pr.Read(b)
        if err == nil {
            fmt.Printf("<- received %q\n", string(b[:n]))
        }
    }
    if err != nil && err != io.EOF {
        fmt.Println("error:", err)
    }
```

完整示例可在[`play.golang.org/p/0YpRK25wFw_c`](https://play.golang.org/p/0YpRK25wFw_c)中找到。

# 扩展读取器

当涉及到传入流时，标准库中有很多函数可用于改进读取器的功能。其中一个最简单的例子是`ioutil.NopCloser`，它接受一个读取器并返回`io.ReadCloser`，什么也不做。如果一个函数负责释放资源，但使用的读取器不是`io.Closer`（比如`bytes.Buffer`），这就很有用。

有两个工具可以限制读取的字节数。`ReadAtLeast`函数定义了要读取的最小字节数。只有在没有要读取的字节时才会返回`EOF`；否则，如果在`EOF`之前读取了较少的字节数，将返回`ErrUnexpectedEOF`。如果字节缓冲区比请求的字节数要短，这是没有意义的，将会返回`ErrShortBuffer`。在读取错误的情况下，函数会设法至少读取所需数量的字节，并且会丢弃该错误。

然后是`ReadFull`，它预期填充缓冲区，否则将返回`ErrUnexpectedEOF`。

另一个约束函数是`LimitReader`。这个函数是一个装饰器，它接收一个读取器并返回另一个读取器，一旦读取到所需的字节，就会返回`EOF`。这可以用于预览实际读取器的内容，就像下面的例子一样：

```go
s := strings.NewReader(`Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged.`)
    io.Copy(os.Stdout, io.LimitReader(s, 25)) // will print "Lorem Ipsum is simply dum"
```

完整的示例可在[`play.golang.org/p/LllOdWg9uyU`](https://play.golang.org/p/LllOdWg9uyU)找到。

更多的读取器可以使用`MultiReader`函数组合成一个序列，将依次读取每个部分，直到达到`EOF`，然后跳转到下一个。

一个读取器和一个写入器可以连接起来，以便来自读取器的任何内容都会被复制到写入器，这与`io.Pipe`的相反情况相反。这是通过`io.TeeReader`完成的。

让我们尝试使用它来创建一个在文件系统中充当搜索引擎的写入器，只打印出与所请求的查询匹配的行。我们想要一个执行以下操作的程序：

+   从参数中读取目录路径和要搜索的字符串

+   获取所选路径中的文件列表

+   读取每个文件，并将包含所选字符串的行传递给另一个写入器

+   另一个写入器将注入颜色字符以突出显示字符串，并将其内容复制到标准输出

让我们从颜色注入开始。在 Unix shell 中，可以通过以下序列获得彩色输出：

+   `\xbb1`: 一个转义字符

+   `[`: 一个开放的括号

+   `39`: 一个数字

+   `m`: 字母*m*

数字确定了背景和前景颜色。对于本例，我们将使用`31`（红色）和`39`（默认）。

我们正在创建一个写入器，它将打印出匹配的行并突出显示文本：

```go
type queryWriter struct {
    Query []byte
    io.Writer
}

func (q queryWriter) Write(b []byte) (n int, err error) {
    lines := bytes.Split(b, []byte{'\n'})
    l := len(q.Query)
    for _, b := range lines {
        i := bytes.Index(b, q.Query)
        if i == -1 {
            continue
        }
        for _, s := range [][]byte{
            b[:i], // what's before the match
            []byte("\x1b[31m"), //star red color
            b[i : i+l], // match
            []byte("\x1b[39m"), // default color
            b[i+l:], // whatever is left
        } {
            v, err := q.Writer.Write(s)
            n += v
            if err != nil {
                return 0, err
            }
        }
        fmt.Fprintln(q.Writer)
    }
    return len(b), nil
}
```

这将与打开文件一起使用`TeeReader`，以便读取文件将写入`queryWriter`：

```go
func main() {
    if len(os.Args) < 3 {
        fmt.Println("Please specify a path and a search string.")
        return
    }
    root, err := filepath.Abs(os.Args[1]) // get absolute path
    if err != nil {
        fmt.Println("Cannot get absolute path:", err)
        return
    }
    q := []byte(strings.Join(os.Args[2:], " "))
    fmt.Printf("Searching for %q in %s...\n", query, root)
    err = filepath.Walk(root, func(path string, info os.FileInfo,   
        err error) error {
            if info.IsDir() {
                return nil
            }
            fmt.Println(path)
            f, err := os.Open(path)
            if err != nil {
                return err
            }
        defer f.Close()

        _, err = ioutil.ReadAll(io.TeeReader(f, queryWriter{q, os.Stdout}))
        return err
    })
    if err != nil {
        fmt.Println(err)
    }
}
```

正如你所看到的，无需写入；从文件中读取会自动写入连接到标准输出的查询写入器。

# 写入器和装饰器

有大量的工具可用于增强、装饰和使用读取器，但对于写入器却不适用。

还有`io.WriteString`函数，它可以防止将字符串转换为字节。首先，它会检查写入器是否支持字符串写入，尝试将其转换为`io.stringWriter`，这是一个只有`WriteString`方法的未导出接口，然后如果成功，写入字符串，否则将其转换为字节。

有`io.MultiWriter`函数，它创建一个写入器，将信息复制到一系列其他写入器中，这些写入器在创建时接收。一个实际的例子是在将内容写入标准输出的同时显示它，就像下面的例子一样：

```go
    r := strings.NewReader("let's read this message\n")
    b := bytes.NewBuffer(nil)
    w := io.MultiWriter(b, os.Stdout)
    io.Copy(w, r) // prints to the standard output
    fmt.Println(b.String()) // buffer also contains string now
```

完整的示例可在[`play.golang.org/p/ZWDF2vCDfsM`](https://play.golang.org/p/ZWDF2vCDfsM)找到。

还有一个有用的变量，`ioutil.Discard`，它是一个写入器，写入到`/dev/null`，一个空设备。这意味着写入到这个变量会忽略数据。

# 总结

在本章中，我们介绍了流的概念，用于描述数据的传入和传出流。我们看到读取器接口表示接收到的数据，而写入器则是发送的数据。

我们比较了标准包中可用的不同读取器。在上一章中我们看了文件，在这一章中我们将字节和字符串读取器加入到列表中。我们学会了如何使用示例实现自定义读取器，并且看到设计一个读取器建立在另一个读取器之上总是一个好主意。

然后，我们专注于写入器。我们发现如果正确打开，文件也是写入器，并且标准包中有几个写入器，包括字节缓冲区和字符串构建器。我们还实现了一个自定义写入器，并看到如何使用`utf8`包处理字节和符文。

最后，我们探索了`io`和`ioutil`中剩余的功能，分析了用于复制数据和连接读取器和写入器的各种工具。我们还看到了用于改进或更改读取器和写入器功能的装饰器。

在下一章中，我们将讨论伪终端应用程序，并利用所有这些知识来构建其中一些。

# 问题

1.  什么是流？

1.  哪些接口抽象了传入流？

1.  哪些接口代表传出流？

1.  何时应该使用字节读取器？何时应该使用字符串读取器？

1.  字符串构建器和字节缓冲区之间有什么区别？

1.  读者和写入者的实现为什么要接受一个接口作为输入？

1.  管道与`TeeReader`有什么不同？


# 第六章：构建伪终端

本章将介绍伪终端应用程序。许多程序（如 SQL 或 SSH 客户端）都是构建为伪终端，因为它能够在终端内进行交互使用。这些类型的应用程序非常重要，因为它们允许我们在没有图形界面的环境中控制应用程序，例如通过**安全外壳**（**SSH**）连接到服务器时。本章将指导您创建一些此类应用程序。

本章将涵盖以下主题：

+   终端和伪终端

+   基本伪终端

+   高级伪终端

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，您可以参考[第三章]（602a92d5-25f7-46b8-83d4-10c6af1c6750.xhtml），*Go 概述*。

# 理解伪终端

伪终端或伪电传打字机是在终端或电传打字机下运行并模拟其行为的应用程序。这是一种非常方便的方式，可以在没有图形界面的终端内运行交互式软件。这是因为它使用终端本身来模拟一个终端。

# 从电传打字机开始

**电传打字机**（**TTY**）或**电传打印机**是通过串行端口控制的电机式打字机的名称。它连接到能够向设备发送信息以打印的计算机上。数据由一系列有限的符号组成，例如 ASCII 字符，具有固定的字体。这些设备作为早期计算机的用户界面，因此它们在某种意义上是现代屏幕的前身。

当屏幕取代打印机作为输出设备时，它们的内容以类似的方式组织：字符的二维矩阵。在早期阶段，它们被称为玻璃 TTY，字符显示仍然是显示本身的一部分，由其自己的逻辑电路控制。随着第一批视频显示卡的到来，计算机能够拥有一个不依赖硬件的界面。

作为操作系统的主要界面使用的仅文本控制台从 TTY 继承其名称，并被称为控制台。即使操作系统运行在现代操作系统上的图形环境中，用户仍然可以访问一定数量的虚拟控制台，这些控制台作为**命令行界面**（**CLI**）使用，通常称为 shell。

# 伪电传打字机

许多应用程序设计为在 shell 内工作，但其中一些是在模仿 shell 的行为。图形界面有一个专门用于执行 shell 的终端模拟器。这些类型的应用程序被称为**伪电传打字机**（**PTY**）。为了被视为 PTY，应用程序需要能够执行以下操作：

+   接受用户输入

+   将输入发送到控制台并接收输出

+   向用户显示此输出

已经有一些示例可用的 Linux 实用程序，其中最显著的是**screen**。这是一个伪终端应用程序，允许用户使用多个 shell 并对其进行控制。它可以打开和关闭新的 shell，并在所有打开的 shell 之间切换。它允许用户命名一个会话，因此，如果由于任何意外原因而被终止，用户可以恢复会话。

# 创建基本 PTY

我们将从创建输入管理器的简单版本的伪终端开始，然后创建命令选择器，最后创建命令执行。

# 输入管理

标准输入可用于接收用户命令。我们可以通过使用缓冲输入来读取行并打印它们。为了读取一行，有一个有用的命令`bufio.Scanner`，它已经提供了一个行读取器。代码将类似于以下代码片段：

```go
s := bufio.NewScanner(os.Stdin)
w := os.Stdout
fmt.Fprint(w, "Some welcome message\n")
for {
    s.Scan() // get next the token
    fmt.Fprint(w, "You wrote \"") 
    w.Write(s.Bytes())
    fmt.Fprintln(w, "\"\n") // writing back the text
}
```

由于此代码没有退出点，我们可以从创建第一个命令`exit`开始，该命令将终止 shell 执行。我们可以对代码进行一些小改动，使其正常工作，如下所示：

```go
s := bufio.NewScanner(os.Stdin)
w := os.Stdout
fmt.Fprint(w, "Some welcome message\n")
for {
    s.Scan() // get next the token
    msg := string(s.Bytes())
    if msg == "exit" {
        return
    }
    fmt.Fprintf (w, "You wrote %q\n", msg) // writing back the text
}
```

现在应用程序有了除`kill`命令之外的退出点。目前，除了`exit`命令之外，它并没有实现任何命令，而只是打印出您输入的任何内容。

# 选择器

为了能够正确解释命令，消息需要被分割成参数。这与操作系统应用于传递给进程的参数的逻辑相同。`strings.Split`函数通过指定空格作为第二个参数并将字符串分割成单词来实现这一点，如下面的代码所示：

```go
args := strings.Split(string(s.Bytes()), " ")
cmd := args[0]
args = args[1:]
```

可以对`cmd`执行任何类型的检查，例如以下的`switch`语句：

```go
switch cmd {
case "exit":
    return
case "someCommand":
    someCommand(w, args)
case "anotherCommand":
    anotherCommand(w, args)
}
```

这允许用户通过定义一个函数并在`switch`语句中添加一个新的`case`来添加新的命令。

# 命令执行

现在一切都准备就绪，唯一剩下的就是定义各种命令将实际执行的操作。我们可以定义执行命令的函数类型以及“switch”的行为：

```go
var cmdFunc func(w io.Writer, args []string) (exit bool)
switch cmd {
case "exit":
    cmdFunc = exitCmd
}
if cmdFunc == nil {
    fmt.Fprintf(w, "%q not found\n", cmd)
    continue
}
if cmdFunc(w, args) { // execute and exit if true
    return
}
```

返回值告诉应用程序是否需要终止，并允许我们轻松定义我们的`exit`函数，而不需要它成为一个特殊情况：

```go
func exitCmd(w io.Writer, args []string) bool {
    fmt.Fprintf(w, "Goodbye! :)")
    return true
}
```

现在我们可以实现任何类型的命令，具体取决于我们应用程序的范围。让我们创建一个`shuffle`命令，它将使用`math`/`rand`包以随机顺序打印参数：

```go
func shuffle(w io.Writer, args ...string) bool {
    rand.Shuffle(len(args), func(i, j int) {
        args[i], args[j] = args[j], args[i]
    })
    for i := range args {
        if i > 0 {
            fmt.Fprint(w, " ")
        }
        fmt.Fprintf(w, "%s", args[i])
    }
    fmt.Fprintln(w)
    return false
}
```

我们可以通过创建一个“print”命令与文件系统和文件进行交互，该命令将在输出中显示文件的内容：

```go
func print(w io.Writer, args ...string) bool {
    if len(args) != 1 {
        fmt.Fprintln(w, "Please specify one file!")
        return false
    }
    f, err := os.Open(args[0])
    if err != nil {
        fmt.Fprintf(w, "Cannot open %s: %s\n", args[0], err)
    }
    defer f.Close()
    if _, err := io.Copy(w, f); err != nil {
        fmt.Fprintf(w, "Cannot print %s: %s\n", args[0], err)
    }
    fmt.Fprintln(w)
    return false
}
```

# 一些重构

伪终端应用程序的当前版本可以通过一些重构来改进。我们可以通过将命令定义为自定义类型，并添加描述其行为的一些方法来开始：

```go
type cmd struct {
    Name string // the command name
    Help string // a description string
    Action func(w io.Writer, args ...string) bool
}

func (c cmd) Match(s string) bool {
  return c.Name == s
}

func (c cmd) Run(w io.Writer, args ...string) bool {
  return c.Action(w, args...)
}
```

每个命令的所有信息都可以包含在一个结构中。我们还可以开始定义依赖其他命令的命令，比如帮助命令。如果我们在`var cmds []cmd`包中定义了一些命令的切片或映射，那么`help`命令将如下所示：

```go
help := cmd{
    Name: "help",
    Help: "Shows available commands",
    Action: func(w io.Writer, args ...string) bool {
        fmt.Fprintln(w, "Available commands:")
        for _, c := range cmds {
            fmt.Fprintf(w, " - %-15s %s\n", c.Name, c.Help)
        }
        return false
    },
}
```

选择正确命令的主循环的部分将略有不同；它需要在切片中找到匹配项并执行它：

```go
for i := range cmds {
    if !cmds[i].Match(args[0]) {
        continue
    }
    idx = i
    break
}
if idx == -1 {
    fmt.Fprintf(w, "%q not found. Use `help` for available commands\n", args[0])
    continue
}
if cmds[idx].Run(w, args[1:]...) {
    fmt.Fprintln(w)
    return
}
```

现在有一个`help`命令，显示了可用命令的列表，我们可以建议用户在每次指定不存在的命令时使用它——就像我们当前检查索引是否已从其默认值`-1`更改一样。

# 改进 PTY

现在我们已经看到如何创建一个基本的伪终端，我们将看到如何通过一些附加功能来改进它。

# 多行输入

可以改进的第一件事是参数和间距之间的关系，通过添加对带引号字符串的支持。这可以通过具有自定义分割函数的`bufio.Scanner`来实现，该函数的行为类似于`bufio.ScanWords`，除了它知道引号的存在。以下代码演示了这一点：

```go
func ScanArgs(data []byte, atEOF bool) (advance int, token []byte, err error) {
    // first space
    start, first := 0, rune(0)
    for width := 0; start < len(data); start += width {
        first, width = utf8.DecodeRune(data[start:])
        if !unicode.IsSpace(first) {
            break
        }
    }
    // skip quote
    if isQuote(first) {
        start++
    }
```

该函数有一个跳过空格并找到第一个非空格字符的第一个块；如果该字符是引号，则跳过它。然后，它查找终止参数的第一个字符，对于普通参数是空格，对于其他参数是相应的引号：

```go
    // loop until arg end character
    for width, i := 0, start; i < len(data); i += width {
        var r rune
        r, width = utf8.DecodeRune(data[i:])
        if ok := isQuote(first); !ok && unicode.IsSpace(r) || ok  
            && r == first {
                return i + width, data[start:i], nil
        }
    }
```

如果在引用上下文中达到文件结尾，则返回部分字符串；否则，不跳过引号并请求更多数据：

```go
    // token from EOF
    if atEOF && len(data) > start {
        return len(data), data[start:], nil
    }
    if isQuote(first) {
        start--
    }
    return start, nil, nil
}
```

完整的示例可在以下链接找到：[`play.golang.org/p/CodJjcpzlLx`](https://play.golang.org/p/CodJjcpzlLx)。

现在我们可以使用这个作为解析参数的行，同时使用如下定义的辅助结构`argsScanner`：

```go
type argsScanner []string

func (a *argsScanner) Reset() { *a = (*a)[0:0] }

func (a *argsScanner) Parse(r io.Reader) (extra string) {
    s := bufio.NewScanner(r)
    s.Split(ScanArgs)
    for s.Scan() {
        *a = append(*a, s.Text())
    }
    if len(*a) == 0 {
        return ""
    }
    lastArg := (*a)[len(*a)-1]
    if !isQuote(rune(lastArg[0])) {
        return ""
    }
    *a = (*a)[:len(*a)-1]
    return lastArg + "\n"
}
```

通过更改循环的工作方式，这个自定义切片将允许我们接收带引号和引号之间的新行的行：

```go
func main() {
 s := bufio.NewScanner(os.Stdin)
 w := os.Stdout
 a := argsScanner{}
 b := bytes.Buffer{}
 for {
        // prompt message 
        a.Reset()
        b.Reset()
        for {
            s.Scan()
            b.Write(s.Bytes())
            extra := a.Parse(&b)
            if extra == "" {
                break
            }
            b.WriteString(extra)
        }
        // a contains the split arguments
    }
}
```

# 为伪终端提供颜色支持

伪终端可以通过提供彩色输出来改进。我们已经看到，在 Unix 中有可以改变背景和前景颜色的转义序列。让我们首先定义一个自定义类型：

```go
type color int

func (c color) Start(w io.Writer) {
    fmt.Fprintf(w, "\x1b[%dm", c)
}

func (c color) End(w io.Writer) {
    fmt.Fprintf(w, "\x1b[%dm", Reset)
}

func (c color) Sprintf(w io.Writer, format string, args ...interface{}) {
    c.Start(w)
    fmt.Fprintf(w, format, args...)
    c.End(w)
}

// List of colors
const (
    Reset color = 0
    Red color = 31
    Green color = 32
    Yellow color = 33
    Blue color = 34
    Magenta color = 35
    Cyan color = 36
    White color = 37
)
```

这种新类型可以用于增强具有彩色输出的命令。例如，让我们使用交替颜色来区分字符串，现在我们支持带有空格的参数的`shuffle`命令：

```go
func shuffle(w io.Writer, args ...string) bool {
    rand.Shuffle(len(args), func(i, j int) {
        args[i], args[j] = args[j], args[i]
    })
    for i := range args {
        if i > 0 {
            fmt.Fprint(w, " ")
        }
        var f func(w io.Writer, format string, args ...interface{})
        if i%2 == 0 {
            f = Red.Fprintf
        } else {
            f = Green.Fprintf
        }
        f(w, "%s", args[i])
    }
    fmt.Fprintln(w)
    return false
}
```

# 建议命令

当指定的命令不存在时，我们可以建议一些类似的命令。为了这样做，我们可以使用 Levenshtein 距离公式，通过计算从一个字符串到另一个字符串所需的删除、插入和替换来衡量字符串之间的相似性。

在下面的代码中，我们将使用`agnivade/levenshtein`包，这将通过`go get`命令获得：

```go
go get github.com/agnivade/levenshtein/...
```

然后，我们定义一个新函数，当现有命令没有匹配时调用：

```go
func commandNotFound(w io.Writer, cmd string) {
    var list []string
    for _, c := range cmds {
        d := levenshtein.ComputeDistance(c.Name, cmd)
        if d < 3 {
            list = append(list, c.Name)
        }
    }
    fmt.Fprintf(w, "Command %q not found.", cmd)
    if len(list) == 0 {
        return
    }
    fmt.Fprint(w, " Maybe you meant: ")
    for i := range list {
        if i > 0 {
            fmt.Fprint(w, ", ")
        }
        fmt.Fprintf(w, "%s", list[i])
    }
}
```

# 可扩展命令

我们伪终端的当前限制是其可扩展性。如果需要添加新命令，需要直接添加到主包中。我们可以考虑一种方法，将命令与主包分离，并允许其他用户使用其命令扩展功能：

1.  第一步是创建一个导出的命令。让我们使用一个接口来定义一个命令，以便用户可以实现自己的命令：

```go
// Command represents a terminal command
type Command interface {
    GetName() string
    GetHelp() string
    Run(input io.Reader, output io.Writer, args ...string) (exit bool)
}
```

1.  现在我们可以指定一系列命令和一个函数，让其他包添加其他命令：

```go
// ErrDuplicateCommand is returned when two commands have the same name
var ErrDuplicateCommand = errors.New("Duplicate command")

var commands []Command

// Register adds the Command to the command list
func Register(command Command) error {
    name := command.GetName()
    for i, c := range commands {
        // unique commands in alphabetical order
        switch strings.Compare(c.GetName(), name) {
        case 0:
            return ErrDuplicateCommand
        case 1:
            commands = append(commands, nil)
            copy(commands[i+1:], commands[i:])
            commands[i] = command
            return nil
        case -1:
            continue
        }
    }
    commands = append(commands, command)
    return nil
}
```

1.  我们可以提供一个命令的基本实现，以执行简单的功能：

```go
// Base is a basic Command that runs a closure
type Base struct {
    Name, Help string
    Action func(input io.Reader, output io.Writer, args ...string) bool
}

func (b Base) String() string { return b.Name }

// GetName returns the Name
func (b Base) GetName() string { return b.Name }

// GetHelp returns the Help
func (b Base) GetHelp() string { return b.Help }

// Run calls the closure
func (b Base) Run(input io.Reader, output io.Writer, args ...string) bool {
    return b.Action(input, output, args...)
}
```

1.  我们可以提供一个函数，将命令与名称匹配：

```go
// GetCommand returns the command with the given name
func GetCommand(name string) Command {
    for _, c := range commands {
        if c.GetName() == name {
            return c
        }
    }
    return suggest
}
```

1.  我们可以使用前面示例中的逻辑，使此函数返回建议的命令，其定义如下：

```go
var suggest = Base{
    Action: func(in io.Reader, w io.Writer, args ...string) bool {
        var list []string
        for _, c := range commands {
            name := c.GetName()
            d := levenshtein.ComputeDistance(name, args[0])
            if d < 3 {
                list = append(list, name)
            }
        }
        fmt.Fprintf(w, "Command %q not found.", args[0])
        if len(list) == 0 {
            return false
        }
        fmt.Fprint(w, " Maybe you meant: ")
        for i := range list {
            if i > 0 {
                fmt.Fprint(w, ", ")
            }
            fmt.Fprintf(w, "%s", list[i])
        }
        return false
    },
}
```

1.  现在我们可以在`exit`和`help`包中注册一些命令。只有`help`可以在这里定义，因为命令列表是私有的：

```go
func init() {
    Register(Base{Name: "help", Help: "...", Action: helpAction})
    Register(Base{Name: "exit", Help: "...", Action: exitAction})
}

func helpAction(in io.Reader, w io.Writer, args ...string) bool {
    fmt.Fprintln(w, "Available commands:")
    for _, c := range commands {
        n := c.GetName()
        fmt.Fprintf(w, " - %-15s %s\n", n, c.GetHelp())
    }
    return false
}

func exitAction(in io.Reader, w io.Writer, args ...string) bool {
    fmt.Fprintf(w, "Goodbye! :)\n")
    return true
}
```

这种方法将允许用户使用`commandBase`结构来创建一个简单的命令，或者嵌入它或使用自定义结构，如果他们的命令需要它（比如带有状态的命令）：

```go
// Embedded unnamed field (inherits method)
type MyCmd struct {
    Base
    MyField string
}

// custom implementation
type MyImpl struct{}

func (MyImpl) GetName() string { return "myimpl" }
func (MyImpl) GetHelp() string { return "help string"}
func (MyImpl) Run(input io.Reader, output io.Writer, args ...string) bool {
    // do something
    return true
}
```

`MyCmd`结构和`MyImpl`结构之间的区别在于一个可以用作另一个命令的装饰器，而第二个是不同的实现，因此它不能与另一个命令交互。

# 带状态的命令

到目前为止，我们已经创建了没有内部状态的命令。但是有些命令可以保持内部状态并相应地改变其行为。状态可以限制在会话本身，也可以跨多个会话共享。最明显的例子是终端中的命令历史，其中执行的所有命令都被存储并在会话之间保留。

# 易失状态

最容易实现的是一个不持久的状态，当应用程序退出时会丢失。我们所需要做的就是创建一个自定义数据结构，托管状态并满足命令接口。方法将属于类型的指针，否则它们将无法修改数据。

在下面的示例中，我们将创建一个非常基本的内存存储，它作为一个堆栈（先进后出）与参数一起工作。让我们从推送和弹出功能开始：

```go
type Stack struct {
    data []string
}

func (s *Stack) push(values ...string) {
    s.data = append(s.data, values...)
}

func (s *Stack) pop() (string, bool) {
    if len(s.data) == 0 {
        return "", false
    }
    v := s.data[len(s.data)-1]
    s.data = s.data[:len(s.data)-1]
    return v, true
}
```

堆栈中存储的字符串表示命令的状态。现在，我们需要实现命令接口的方法——我们可以从最简单的开始：

```go
func (s *Stack) GetName() string {
    return "stack"
}

func (s *Stack) GetHelp() string {
    return "a stack-like memory storage"
}
```

现在我们需要决定它在内部是如何工作的。将有两个子命令：

+   `push`，后跟一个或多个参数，将推送到堆栈。

+   `pop`将取出堆栈的顶部元素，不需要任何参数。

让我们定义一个辅助方法`isValid`，检查参数是否有效：

```go
func (s *Stack) isValid(cmd string, args []string) bool {
    switch cmd {
    case "pop":
        return len(args) == 0
    case "push":
        return len(args) > 0
    default:
        return false
    }
}
```

现在，我们可以实现命令执行方法，它将使用有效性检查。如果通过了这一点，它将执行所选的命令或显示帮助消息：

```go
func (s *Stack) Run(r io.Reader, w io.Writer, args ...string) (exit bool) {
    if l := len(args); l < 2 || !s.isValid(args[1], args[2:]) {
        fmt.Fprintf(w, "Use `stack push <something>` or `stack pop`\n")
        return false
    }
    if args[1] == "push" {
        s.push(args[2:]...)
        return false
    }
    if v, ok := s.pop(); !ok {
        fmt.Fprintf(w, "Empty!\n")
    } else {
        fmt.Fprintf(w, "Got: `%s`\n", v)
    }
    return false
}
```

# 持久状态

下一步是在会话之间持久化状态，这需要在应用程序启动时执行一些操作，并在应用程序结束时执行另一些操作。这些新行为可以与命令接口的一些更改集成：

```go
type Command interface {
    Startup() error
    Shutdown() error
    GetName() string
    GetHelp() string
    Run(r io.Reader, w io.Writer, args ...string) (exit bool)
}
```

`Startup()`方法负责在应用程序启动时加载状态，`Shutdown()`方法需要在`exit`之前将当前状态保存到磁盘。我们可以使用这些方法更新`Base`结构；但是，这不会做任何事情，因为没有状态：

```go
// Startup does nothing
func (b Base) Startup() error { return nil }

// Shutdown does nothing
func (b Base) Shutdown() error { return nil }
```

命令列表没有被导出；它是未导出的变量`commands`。我们可以添加两个函数，这些函数将与这样一个列表进行交互，并确保我们在所有可用的命令上执行这些方法，`Startup`和`Shutdown`：

```go
// Shutdown executes shutdown for all commands
func Shutdown(w io.Writer) {
    for _, c := range commands {
        if err := c.Shutdown(); err != nil {
            fmt.Fprintf(w, "%s: shutdown error: %s", c.GetName(), err)
        }
    }
}

// Startup executes Startup for all commands
func Startup(w io.Writer) {
    for _, c := range commands {
        if err := c.Startup(); err != nil {
            fmt.Fprintf(w, "%s: startup error: %s", c.GetName(), err)
        }
    }
}
```

最后一步是在主循环开始之前在主应用程序中使用这些函数：

```go
func main() {
    s, w, a, b := bufio.NewScanner(os.Stdin), os.Stdout, args{}, bytes.Buffer{}
    command.Startup(w)
    defer command.Shutdown(w) // this is executed before returning
    fmt.Fprint(w, "** Welcome to PseudoTerm! **\nPlease enter a command.\n")
    for {
        // main loop
    }
}
```

# 升级 Stack 命令

我们希望之前定义的`Stack`命令能够在会话之间保存其状态。最简单的解决方案是将堆栈的内容保存为文本文件，每行一个元素。我们可以使用 OS/user 包将此文件对每个用户设置为唯一，并将其放置在用户的`home`目录中：

```go
func (s *Stack) getPath() (string, error) {
    u, err := user.Current()
    if err != nil {
        return "", err
    }
    return filepath.Join(u.HomeDir, ".stack"), nil
}
```

让我们开始写作；我们将创建并截断文件（使用`TRUNC`标志将其大小设置为`0`），并写入以下行：

```go
func (s *Stack) Shutdown(w io.Writer) error {
    path, err := s.getPath()
    if err != nil {
        return err
    }
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    defer f.Close()
    for _, v := range s.data {
        if _, err := fmt.Fprintln(f, v); err != nil {
            return err
        }
    }
    return nil
}
```

在关闭期间使用的方法将逐行读取文件，并将元素添加到堆栈中。我们可以使用`bufio.Scanner`，就像我们在之前的章节中看到的那样，轻松地做到这一点：

```go
func (s *Stack) Startup(w io.Writer) error {
    path, err := s.getPath()
    if err != nil {
        return err
    }
    f, err := os.Open(path)
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return err
    }
    defer f.Close()
    s.data = s.data[:0]
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        s.push(string(scanner.Bytes()))
    }
    return nil
}
```

# 总结

在本章中，我们通过一些术语，以便理解为什么现代终端应用程序存在以及它们是如何发展的。

然后，我们专注于如何实现基本的伪终端。第一步是创建一个处理输入管理的循环，然后需要创建一个命令选择器，最后是一个执行器。选择器可以在包中选择一系列定义的函数，并且我们创建了一个特殊的命令来退出应用程序。通过一些重构，我们从函数转变为包含名称和操作的结构体。

我们看到了如何以各种方式改进应用程序。首先，我们创建了对多行输入的支持（使用自定义的分割函数来支持带引号的字符串，以及换行符）。然后，我们创建了一些工具来为我们的函数添加有色输出，并在之前定义的某个命令中使用它们。当用户指定一个不存在的命令时，我们还使用 Levenshtein 距离来建议类似的命令。

最后，我们将命令与主应用程序分离，并创建了一种从外部注册新命令的方式。我们使用了接口，因为这允许更好的扩展和定制，以及接口的基本实现。

在下一章中，我们将开始讨论进程属性和子进程。

# 问题

1.  什么是终端，什么是伪终端？

1.  伪终端应该能够做什么？

1.  我们使用了哪些 Go 工具来模拟终端？

1.  我的应用程序如何从标准输入获取指令？

1.  使用接口来实现命令有什么优势？

1.  Levenshtein 距离是什么？为什么在伪终端中有用？


# 第三部分：理解进程通信

本节探讨了各种进程如何相互通信。它解释了如何在 Go 中使用基于 Unix 的管道通信，如何在应用程序内部处理信号，以及如何有效地使用网络进行通信。最后，它展示了如何对数据进行编码以提高通信速度。

本节包括以下章节：

+   第七章，处理进程和守护进程

+   第八章，退出代码、信号和管道

+   第九章，网络编程

+   第十章，使用 Go 进行数据编码


# 第七章：处理进程和守护进程

本章将介绍如何使用 Go 标准库处理当前进程的属性，以及如何更改它们。我们还将重点介绍如何创建子进程，并概述`os/exec`包。

最后，我们将解释守护进程是什么，它们具有什么属性，以及如何使用标准库创建它们。

本章将涵盖以下主题：

+   理解进程

+   子进程

+   从守护进程开始

+   创建服务

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，您可以参考第三章，*Go 概述*。

# 理解进程

我们已经看到了 Unix 操作系统中进程的重要性，现在我们将看看如何获取有关当前进程的信息以及如何创建和处理子进程。

# 当前进程

Go 标准库允许我们获取有关当前进程的信息。这是通过使用`os`包中提供的一系列函数来完成的。

# 标准输入

程序可能想要知道的第一件事是它的标识符和父标识符，即 PID 和 PPID。这实际上非常简单 - `os.Getpid()`和`os.Getppid()`函数都返回一个整数值，其中包含这两个标识符，如下面的代码所示：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    fmt.Println("Current PID:", os.Getpid())
    fmt.Println("Current Parent PID:", os.Getppid())
}
```

完整示例可在[`play.golang.org/p/ng0m9y4LcD5`](https://play.golang.org/p/ng0m9y4LcD5)找到。

# 用户和组 ID

另一个有用的信息是当前用户和进程所属的组。一个典型的用例可能是将它们与特定文件的权限进行比较。

`os`包提供以下功能：

+   `os.Getuid()`: 返回进程所有者的用户 ID

+   `os.Getgid()`: 返回进程所有者的组 ID

+   `os.Getgroups()`: 返回进程所有者的附加组 ID

我们可以看到这三个函数返回它们的数字形式的 ID：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    fmt.Println("User ID:", os.Getuid())
    fmt.Println("Group ID:", os.Getgid())
    groups, err := os.Getgroups()
    if err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println("Group IDs:", groups)
}
```

完整示例可在[`play.golang.org/p/EqmonEEc_ZI`](https://play.golang.org/p/EqmonEEc_ZI)找到。

为了获取用户和组的名称，`os/user`包中有一些辅助函数。这些函数（名称相当自明）如下：

+   `func LookupGroupId(gid string) (*Group, error)`

+   `func LookupId(uid string) (*User, error)`

即使用户 ID 是一个整数，它需要一个字符串作为参数，因此需要进行转换。最简单的方法是使用`strconv`包，它提供了一系列实用程序，用于将字符串转换为其他基本数据类型，反之亦然。

我们可以在以下示例中看到它们的作用：

```go
package main

import (
    "fmt"
    "os"
    "os/user"
    "strconv"
)

func main() {
    uid := os.Getuid()
    u, err := user.LookupId(strconv.Itoa(uid))
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    fmt.Printf("User: %s (uid %d)\n", u.Username, uid)
    gid := os.Getgid()
    group, err := user.LookupGroupId(strconv.Itoa(gid))
    if err != nil {
        fmt.Println("Error:", err)
        return
    }
    fmt.Printf("Group: %s (uid %d)\n", group.Name, uid)
}
```

完整示例可在[`play.golang.org/p/C6EWF2c50DT`](https://play.golang.org/p/C6EWF2c50DT)找到。

# 工作目录

进程可以提供给我们的另一个非常有用的信息是工作目录，以便我们可以更改它。在第四章，*与文件系统一起工作*中，我们了解了可以使用的工具 - `os.Getwd`和`os.Chdir`。

在以下实际示例中，我们将看看如何使用这些函数来操作工作目录：

1.  首先，我们将获取当前工作目录，并使用它获取二进制文件的路径。

1.  然后，我们将工作目录与另一个路径连接起来，并使用它创建一个目录。

1.  最后，我们将使用刚创建的目录的路径来更改当前工作目录。

查看以下代码：

```go
// obtain working directory
wd, err := os.Getwd()
if err != nil {
    fmt.Println("Error:", err)
    return
}
fmt.Println("Working Directory:", wd)
fmt.Println("Application:", filepath.Join(wd, os.Args[0]))

// create a new directory
d := filepath.Join(wd, "test")
if err := os.Mkdir(d, 0755); err != nil {
    fmt.Println("Error:", err)
    return
}
fmt.Println("Created", d)

// change the current directory
if err := os.Chdir(d); err != nil {
    fmt.Println("Error:", err)
    return
}
fmt.Println("New Working Directory:", d)
```

完整示例可在[`play.golang.org/p/UXAer5nGBtm`](https://play.golang.org/p/UXAer5nGBtm)找到。

# 子进程

Go 应用程序可以与操作系统交互，创建其他进程。`os`的另一个子包提供了创建和运行新进程的功能。在`os/exec`包中，有一个`Cmd`类型，表示命令执行：

```go
type Cmd struct {
    Path string // command to run.
    Args []string // command line arguments (including command)
    Env []string // environment of the process
    Dir string // working directory
    Stdin io.Reader // standard input`
    Stdout io.Writer // standard output
    Stderr io.Writer // standard error
    ExtraFiles []*os.File // additional open files
    SysProcAttr *syscall.SysProcAttr // os specific attributes
    Process *os.Process // underlying process
    ProcessState *os.ProcessState // information on exited processte
}
```

创建新命令的最简单方法是使用`exec.Command`函数，它接受可执行路径和一系列参数。让我们看一个简单的例子，使用`echo`命令和一些参数：

```go
package main

import (
    "fmt"
    "os/exec"
)

func main() {
    cmd := exec.Command("echo", "A", "sample", "command")
    fmt.Println(cmd.Path, cmd.Args[1:]) // echo [A sample command]
}
```

完整的示例可在[`play.golang.org/p/dBIAUteJbxI`](https://play.golang.org/p/dBIAUteJbxI)找到。

一个非常重要的细节是标准输入、输出和错误的性质-它们都是我们已经熟悉的接口：

+   输入是一个`io.Reader`，可以是`bytes.Reader`、`bytes.Buffer`、`strings.Reader`、`os.File`或任何其他实现。

+   输出和错误都是`io.Writer`，也可以是`os.File`或`bytes.Buffer`，也可以是`strings.Builder`或任何其他的写入器实现。

根据父应用程序的需求，有不同的启动进程的方式：

+   `Cmd.Run`：执行命令，并返回一个错误，如果子进程正确执行，则为`nil`。

+   `Cmd.Start`：异步执行命令，并让父进程继续其流程。为了等待子进程完成执行，还有另一种方法`Cmd.Wait`。

+   `Cmd.Output`：执行命令并返回其标准输出，如果`Stderr`未定义但标准错误产生了输出，则返回错误。

+   `Cmd.CombinedOutput`：执行命令并返回标准错误和输出的组合，当需要检查或保存子进程的整个输出-标准输出加标准错误时非常有用。

# 访问子属性

一旦命令开始执行，同步或异步，底层的`os.Process`就会被填充，可以看到它的 PID，就像下面的例子中所示的那样：

```go
package main

import (
    "fmt"
    "os/exec"
)

func main() {
    cmd := exec.Command("ls", "-l")
    if err := cmd.Start(); err != nil {
        fmt.Println(err)
        return
    }
    fmt.Println("Cmd: ", cmd.Args[0])
    fmt.Println("Args:", cmd.Args[1:])
    fmt.Println("PID: ", cmd.Process.Pid)
    cmd.Wait()
}
```

# 标准输入

标准输入可以用来从应用程序向子进程发送一些数据。可以使用缓冲区来存储数据，并让命令读取它，就像下面的例子中所示的那样：

```go
package main

import (
    "bytes"
    "fmt"
    "os"
    "os/exec"
)

func main() {
    b := bytes.NewBuffer(nil)
    cmd := exec.Command("cat")
    cmd.Stdin = b
    cmd.Stdout = os.Stdout
    fmt.Fprintf(b, "Hello World! I'm using this memory address: %p", b)
    if err := cmd.Start(); err != nil {
        fmt.Println(err)
        return
    }
    cmd.Wait()
}
```

# 从守护进程开始

在 Unix 中，所有在后台运行的程序都被称为**守护进程**。它们通常以字母*d*结尾，比如`sshd`或`syslogd`，并提供操作系统的许多功能。

# 操作系统支持

在 macOS、Unix 和 Linux 中，如果一个进程在其父进程生命周期结束后仍然存在，那么它就是一个守护进程，这是因为父进程终止执行后，子进程的父进程会变成`init`进程，一个没有父进程的特殊守护进程，PID 为 1，它随着操作系统的启动和终止而启动和终止。在进一步讨论之前，让我们介绍两个非常重要的概念- *会话* 和 *进程组*：

+   进程组是一组共享信号处理的进程。该组的第一个进程称为**组长**。有一个 Unix 系统调用`setpgid`，可以改变进程的组，但有一些限制。进程可以在`exec`系统调用执行之前改变自己的进程组，或者改变其一个子进程的组。当进程组改变时，会话组也需要相应地改变，目标组的领导者也是如此。

+   会话是一组进程组，允许我们对进程组和其他操作施加一系列限制。会话不允许进程组迁移到另一个会话，并且阻止进程在不同会话中创建进程组。`setsid`系统调用允许我们改变进程会话到一个新的会话，如果进程不是进程组领导者。此外，第一个进程组 ID 设置为会话 ID。如果这个 ID 与正在运行的进程的 ID 相同，那么该进程被称为**会话领导者**。

现在我们已经解释了这两个属性，我们可以看看创建守护进程所需的标准操作，通常包括以下操作：

+   清理环境以删除不必要的变量。

+   创建一个 fork，以便主进程可以正常终止进程。

+   使用`setsid`系统调用，完成以下三个步骤：

1.  从 fork 的进程中删除 PPID，以便它被`init`进程接管

1.  为 fork 创建一个新的会话，这将成为会话领导者

1.  将进程设置为组领导者

+   fork 的当前目录设置为根目录，以避免使用其他目录，并且父进程打开的所有文件都被关闭（如果需要，子进程将打开它们）。

+   将标准输入设置为`/dev/null`，并使用一些日志文件作为标准输出和错误。

+   可选地，fork 可以再次 fork，然后退出。第一个 fork 将成为组领导者，第二个将具有相同的组，允许我们有另一个不是组领导者的 fork。

这对基于 Unix 的操作系统有效，尽管 Windows 也支持永久后台进程，称为**服务**。服务可以在启动时自动启动，也可以使用名为**服务控制管理器**（**SCM**）的可视应用程序手动启动和停止。它们还可以通过常规提示中的`sc`命令以及 PowerShell 中的`Start-Service`和`Stop-Service` cmdlet 来进行控制。

# 守护进程的操作

现在我们了解了守护进程是什么以及它是如何工作的，我们可以尝试使用 Go 标准库来创建一个。Go 应用程序是多线程的，不允许直接调用`fork`系统调用。

我们已经学会了`os/exec`包中的`Cmd.Start`方法允许我们异步启动一个进程。第二步是使用`release`方法关闭当前进程的所有资源。

以下示例向我们展示了如何做到这一点：

```go
package main

import (
    "fmt"
    "os"
    "os/exec"
    "time"
)

var pid = os.Getpid()

func main() {
    fmt.Printf("[%d] Start\n", pid)
    fmt.Printf("[%d] PPID: %d\n", pid, os.Getppid())
    defer fmt.Printf("[%d] Exit\n\n", pid)
    if len(os.Args) != 1 {
        runDaemon()
        return
    }
    if err := forkProcess(); err != nil {
        fmt.Printf("[%d] Fork error: %s\n", pid, err)
        return
    }
    if err := releaseResources(); err != nil {
        fmt.Printf("[%d] Release error: %s\n", pid, err)
        return
    }
}
```

让我们看看`forkProcess`函数的作用，创建另一个进程，并启动它：

1.  首先，进程的工作目录被设置为根目录，并且输出和错误流被设置为标准流：

```go
func forkProcess() error {
    cmd := exec.Command(os.Args[0], "daemon")
    cmd.Stdout, cmd.Stderr, cmd.Dir = os.Stdout, os.Stderr, "/"
    return cmd.Start()
}
```

1.  然后，我们可以释放资源 - 首先，我们需要找到当前进程。然后，我们可以调用`os.Process`方法`Release`，以确保主进程释放其资源：

```go
func releaseResources() error {
    p, err := os.FindProcess(pid)
    if err != nil {
        return err
    }
    return p.Release()
}
```

1.  `main`函数将包含守护逻辑，在这个例子中非常简单 - 它将每隔几秒打印正在运行的内容。

```go
func runDaemon() {
    for {
        fmt.Printf("[%d] Daemon mode\n", pid)
        time.Sleep(time.Second * 10)
    }
}
```

# 服务

我们已经看到了从引导到操作系统关闭的第一个进程被称为`init`或`init.d`，因为它是一个守护进程。这个进程负责处理其他守护进程，并将其配置存储在`/etc/init.d`目录中。

每个 Linux 发行版都使用自己的守护进程控制过程版本，例如 Chrome OS 中的`upstart`或 Arch Linux 中的`systemd`。它们都有相同的目的并且行为类似。

每个守护进程都有一个控制脚本或应用程序，驻留在`/etc/init.d`中，并且应该能够解释一系列命令作为第一个参数，例如`status`，`start`，`stop`和`restart`。在大多数情况下，`init.d`文件是一个脚本，根据参数执行开关并相应地行为。

# 创建一个服务

一些应用程序能够自动处理它们的服务文件，这就是我们将逐步尝试实现的内容。让我们从一个`init.d`脚本开始：

```go
#!/bin/sh

"/path/to/mydaemon" $1
```

这是一个将第一个参数传递给守护程序的示例脚本。二进制文件的路径将取决于文件的位置。这需要在运行时定义：

```go
// ErrSudo is an error that suggest to execute the command as super user
// It will be used with the functions that fail because of permissions
var ErrSudo error

var (
    bin string
    cmd string
)

func init() {
    p, err := filepath.Abs(filepath.Dir(os.Args[0]))
    if err != nil {
        panic(err)
    }
    bin = p
    if len(os.Args) != 1 {
        cmd = os.Args[1]
    }
    ErrSudo = fmt.Errorf("try `sudo %s %s`", bin, cmd)
}
```

`main`函数将处理不同的命令，如下所示：

```go
func main() {
    var err error
    switch cmd {
    case "run":
        err = runApp()
    case "install":
        err = installApp()
    case "uninstall":
        err = uninstallApp()
    case "status":
        err = statusApp()
    case "start":
        err = startApp()
    case "stop":
        err = stopApp()
    default:
        helpApp()
    }
    if err != nil {
        fmt.Println(cmd, "error:", err)
    }
}
```

我们如何确保我们的应用程序正在运行？一个非常可靠的策略是使用`PID`文件，这是一个包含正在运行进程的当前 PID 的文本文件。让我们定义一些辅助函数来实现这一点：

```go
const (
    varDir = "/var/mydaemon/"
    pidFile = "mydaemon.pid"
)

func writePid(pid int) (err error) {
    f, err := os.OpenFile(filepath.Join(varDir, pidFile), os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()
    if _, err = fmt.Fprintf(f, "%d", pid); err != nil {
        return err
    }
    return nil
}

func getPid() (pid int, err error) {
    b, err := ioutil.ReadFile(filepath.Join(varDir, pidFile))
    if err != nil {
        return 0, err
    }
    if pid, err = strconv.Atoi(string(b)); err != nil {
        return 0, fmt.Errorf("Invalid PID value: %s", string(b))
    }
    return pid, nil
}
```

`install`和`uninstall`函数将负责添加或删除位于`/etc/init.d/mydaemon`的服务文件，并要求我们以 root 权限启动应用程序，因为文件的位置：

```go
const initdFile = "/etc/init.d/mydaemon"

func installApp() error {
    _, err := os.Stat(initdFile)
    if err == nil {
        return errors.New("Already installed")
    }
    f, err := os.OpenFile(initdFile, os.O_CREATE|os.O_WRONLY, 0755)
    if err != nil {
        if !os.IsPermission(err) {
            return err
        }
        return ErrSudo
    }
    defer f.Close()
    if _, err = fmt.Fprintf(f, "#!/bin/sh\n\"%s\" $1", bin); err != nil {
        return err
    }
    fmt.Println("Daemon", bin, "installed")
    return nil
}

func uninstallApp() error {
    _, err := os.Stat(initdFile)
    if err != nil && os.IsNotExist(err) {
        return errors.New("not installed")
    }
    if err = os.Remove(initdFile); err != nil {
        if err != nil {
            if !os.IsPermission(err) {
                return err
            }
       return ErrSudo
        }
    }
    fmt.Println("Daemon", bin, "removed")
    return err
}
```

创建文件后，我们可以使用`mydaemon install`命令将应用程序安装为服务，并使用`mydaemon uninstall`命令将其删除。

守护程序安装完成后，我们可以使用`sudo service mydaemon [start|stop|status]`来控制守护程序。现在，我们只需要实现这些操作：

+   `status`将查找`pid`文件，读取它，并向进程发送信号以检查它是否正在运行。

+   `start`将使用`run`命令运行应用程序，并写入`pid`文件。

+   `stop`将获取`pid`文件，找到进程，杀死它，然后删除`pid`文件。

让我们看看`status`命令是如何实现的。请注意，在 Unix 中不存在`0`信号，并且不会触发操作系统或应用程序的操作，但如果进程没有运行，操作将失败。这告诉我们进程是否存活：

```go
func statusApp() (err error) {
    var pid int
    defer func() {
        if pid == 0 {
            fmt.Println("status: not active")
            return
        }
        fmt.Println("status: active - pid", pid)
    }()
    pid, err = getPid()
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return err
    }
    p, err := os.FindProcess(pid)
    if err != nil {
        return nil
    }
    if err = p.Signal(syscall.Signal(0)); err != nil {
        fmt.Println(pid, "not found - removing PID file...")
        os.Remove(filepath.Join(varDir, pidFile))
        pid = 0
    }
    return nil
}
```

在`start`命令中，我们将按照*操作系统支持*部分中介绍的步骤创建守护程序：

1.  使用文件进行标准输出和输入

1.  将工作目录设置为根目录

1.  异步启动命令

除了这些操作，`start`命令还将进程的 PID 值保存在特定文件中，用于查看进程是否存活：

```go
func startApp() (err error) {
    const perm = os.O_CREATE | os.O_APPEND | os.O_WRONLY
    if err = os.MkdirAll(varDir, 0755); err != nil {
        if !os.IsPermission(err) {
            return err
        }
        return ErrSudo
    }
    cmd := exec.Command(bin, "run")
    cmd.Stdout, err = os.OpenFile(filepath.Join(varDir, outFile),  
        perm, 0644)
            if err != nil {
                 return err
            }
    cmd.Stderr, err = os.OpenFile(filepath.Join(varDir, errFile), 
        perm, 0644)
            if err != nil {
                return err
           }
    cmd.Dir = "/"
    if err = cmd.Start(); err != nil {
        return err
    }
    if err := writePid(cmd.Process.Pid); err != nil {
        if err := cmd.Process.Kill(); err != nil {
            fmt.Println("Cannot kill process", cmd.Process.Pid, err)
        }
        return err
    }
    fmt.Println("Started with PID", cmd.Process.Pid)
    return nil
}
```

最后，`stopApp`将终止由 PID 文件标识的进程（如果存在）：

```go
func stopApp() (err error) {
    pid, err := getPid()
    if err != nil {
        if os.IsNotExist(err) {
            return nil
        }
        return err
    }
    p, err := os.FindProcess(pid)
    if err != nil {
        return nil
    }
    if err = p.Signal(os.Kill); err != nil {
        return err
    }
    if err := os.Remove(filepath.Join(varDir, pidFile)); err != nil {
        return err
    }
    fmt.Println("Stopped PID", pid)
    return nil
}
```

现在，应用程序控制所需的所有部分都已经准备就绪，唯一缺少的是主应用程序部分，它应该是一个循环，以便守护程序保持活动状态：

```go
func runApp() error {
    fmt.Println("RUN")
    for {
        time.Sleep(time.Second)
    }
    return nil
}
```

在这个例子中，它只是在循环迭代之间固定时间睡眠。这通常是在主循环中一个好主意，因为一个空的`for`循环会无缘无故地使用大量资源。假设你的应用程序在`for`循环中检查某个条件。如果满足条件，不断检查这个条件会消耗大量资源。添加几毫秒的空闲睡眠可以帮助减少 90-95%的空闲 CPU 消耗，因此在设计守护程序时请记住这一点！

# 第三方包

到目前为止，我们已经看到了如何使用`init.d`服务从头开始实现守护程序。我们的实现非常简单和有限。它可以改进，但已经有许多包提供了相同的功能。它们支持不同的提供者，如`init.d`和`systemd`，其中一些还可以在 Windows 等非 Unix 操作系统上工作。

其中一个更有名的包（在 GitHub 上有 1000 多个星）是`kardianos/service`，它支持所有主要平台 - Linux、macOS 和 Windows。

它定义了一个表示守护程序的主接口，并具有两种方法 - 一种用于启动守护程序，另一种用于停止它。两者都是非阻塞的：

```go
type Interface interface {
    // Start provides a place to initiate the service. The service doesn't not
    // signal a completed start until after this function returns, so the
    // Start function must not take more than a few seconds at most.
    Start(s Service) error

    // Stop provides a place to clean up program execution before it is terminated.
    // It should not take more than a few seconds to execute.
    // Stop should not call os.Exit directly in the function.
    Stop(s Service) error
}
```

该包已经提供了一些用例，从简单到更复杂的用例，在示例（[`github.com/kardianos/service/tree/master/example`](https://github.com/kardianos/service/tree/master/example)）目录中。最佳实践是使用主活动循环启动一个 goroutine。`Start`方法可用于打开和准备必要的资源，而`Stop`应该用于释放它们，以及其他延迟活动，如缓冲区刷新。

一些其他包只与 Unix 系统兼容，比如`takama/daemon`（[`github.com/takama/daemon`](https://github.com/takama/daemon)），它的工作方式类似。它也提供了一些使用示例。

# 总结

在本章中，我们回顾了如何获取与当前进程相关的信息，如 PID 和 PPID，UID 和 GID，以及工作目录。然后，我们看到了`os/exec`包如何允许我们创建子进程，以及如何读取它们的属性，类似于当前进程。

接下来，我们看了一下守护程序是什么，以及各种操作系统如何支持它们。我们验证了使用`os/exec`的`Cmd.Run`来执行一个超出其父进程生存期的进程是多么简单。

然后，我们通过 Unix 提供的自动化守护程序管理系统，逐步创建了一个能够通过`service`运行的应用程序。

在下一章中，我们将通过查看如何使用退出代码以及如何管理和发送信号来提高我们对子进程的控制。

# 问题

1.  Go 应用程序中有哪些关于当前进程的信息可用？

1.  如何创建一个子进程？

1.  如何确保子进程能够生存其父进程？

1.  你能访问子属性吗？你如何使用它们？

1.  Linux 中的守护程序是什么，它们是如何处理的？
