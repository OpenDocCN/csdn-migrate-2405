# Go 系统编程实用指南（六）

> 原文：[`zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA`](https://zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：实现并发模式

本章将介绍并发模式以及如何使用它们构建健壮的系统应用程序。我们已经看过了所有涉及并发的工具（goroutines 和通道，`sync`和`atomic`，以及上下文），现在我们将看一些常见的组合模式，以便我们可以在程序中使用它们。

本章将涵盖以下主题：

+   从生成器开始

+   通过管道进行排序

+   复用和解复用

+   其他模式

+   资源泄漏

# 技术要求

这一章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅[第三章]（602a92d5-25f7-46b8-83d4-10c6af1c6750.xhtml），*Go 概述*。

# 从生成器开始

生成器是一个每次调用时返回序列的下一个值的函数。使用生成器的最大优势是惰性创建序列的新值。在 Go 中，这可以用接口或通道来表示。当生成器与通道一起使用时，其中一个优点是它们以并发方式产生值，在单独的 goroutine 中，使主 goroutine 能够执行其他类型的操作。

可以用一个非常简单的接口来抽象化：

```go
type Generator interface {
    Next() interface{}
}

type GenInt64 interface {
    Next() int64
}
```

接口的返回类型将取决于用例，在我们的情况下是`int64`。它的基本实现可以是一个简单的计数器：

```go
type genInt64 int64

func (g *genInt64) Next() int64 {
    *g++
    return int64(*g)
}
```

这个实现不是线程安全的，所以如果我们尝试在 goroutine 中使用它，可能会丢失一些元素：

```go
func main() {
    var g genInt64
    for i := 0; i < 1000; i++ {
        go func(i int) {
            fmt.Println(i, g.Next())
        }(i)
    }
    time.Sleep(time.Second)
}
```

使生成器并发的一个简单方法是对整数执行原子操作。

这将使并发生成器线程安全，代码需要进行很少的更改：

```go
type genInt64 int64

func (g *genInt64) Next() int64 {
    return atomic.AddInt64((*int64)(g), 1)
}
```

这将避免应用程序中的竞争条件。但是，还有另一种可能的实现，但这需要使用通道。其思想是在 goroutine 中生成值，然后将其传递到共享通道中的下一个方法，如下例所示：

```go
type genInt64 struct {
    ch chan int64
}

func (g genInt64) Next() int64 {
    return <-g.ch
}

func NewGenInt64() genInt64 {
    g := genInt64{ch: make(chan int64)}
    go func() {
        for i := int64(0); ; i++ {
            g.ch <- i
        }
    }()
    return g
}
```

循环将永远继续，并且在生成器用户停止使用`Next`方法请求新值时，将在发送操作中阻塞。

代码之所以以这种方式结构化，是因为我们试图实现我们在开头定义的接口。我们也可以只返回一个通道并用它进行接收：

```go
func GenInt64() <-chan int64 {
 ch:= make(chan int64)
    go func() {
        for i := int64(0); ; i++ {
            ch <- i
        }
    }()
    return ch
}
```

直接使用通道的主要优势是可以将其包含在`select`语句中，以便在不同的通道操作之间进行选择。以下显示了两个不同生成器之间的`select`：

```go
func main() {
    ch1, ch2 := GenInt64(), GenInt64()
    for i := 0; i < 20; i++ {
        select {
        case v := <-ch1:
            fmt.Println("ch 1", v)
        case v := <-ch2:
            fmt.Println("ch 2", v)
        }
    }
}
```

# 避免泄漏

允许循环结束是个好主意，以避免 goroutine 和资源泄漏。其中一些问题如下：

+   当 goroutine 挂起而不返回时，内存中的空间仍然被使用，导致应用程序在内存中的大小增加。只有当 goroutine 返回或发生 panic 时，GC 才会收集 goroutine 和堆栈中定义的变量。

+   如果文件保持打开状态，这可能会阻止其他进程对其执行操作。如果打开的文件数量达到操作系统强加的限制，进程将无法打开其他文件（或接受网络连接）。

这个问题的一个简单解决方案是始终使用`context.Context`，这样您就有了 goroutine 的明确定义的退出点：

```go
func NewGenInt64(ctx context.Context) genInt64 {
    g := genInt64{ch: make(chan int64)}
    go func() {
        for i := int64(0); ; i++ {
            select {
            case g.ch <- i:
                // do nothing
            case <-ctx.Done():
                close(g.ch)
                return
            }
        }
    }()
    return g
}
```

这可以用于生成值，直到需要它们并在不需要新值时取消上下文。相同的模式也可以应用于返回通道的版本。例如，我们可以直接使用`cancel`函数或在上下文上设置超时：

```go
func main() {
    ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
    defer cancel()
    g := NewGenInt64(ctx)
    for i := range g.ch {
        go func(i int64) {
            fmt.Println(i, g.Next())
        }(i)
    }
    time.Sleep(time.Second)
}
```

生成器将生成数字，直到提供的上下文到期。此时，生成器将关闭通道。

# 通过管道进行排序

管道是一种结构化应用程序流程的方式，通过将主要执行分成可以使用某种通信手段相互交谈的阶段来实现。这可以是以下之一：

+   外部，比如网络连接或文件

+   应用程序内部，如 Go 的通道

第一个阶段通常被称为生产者，而最后一个通常被称为消费者。

Go 提供的并发工具集允许我们有效地使用多个 CPU，并通过阻塞输入或输出操作来优化它们的使用。通道特别适用于内部管道通信。它们可以由接收入站通道并返回出站通道的函数表示。基本结构看起来像这样：

```go
func stage(in <-chan interface{}) <-chan interface{} {
    var out = make(chan interface{})
    go func() {
        for v := range in {
            v = v.(int)+1 // some operation
            out <- v
        }
        close(out)
    }()
    return out
}
```

我们创建一个与输入通道相同类型的通道并返回它。在一个单独的 goroutine 中，我们从输入通道接收数据，对数据执行操作，然后将其发送到输出通道。

这种模式可以通过使用`context.Context`进一步改进，以便我们更好地控制应用程序流程。它看起来像以下代码：

```go
func stage(ctx context.Context, in <-chan interface{}) <-chan interface{} {
    var out = make(chan interface{})
    go func() {
        defer close(out)
        for v := range in {
            v = v.(int)+1 // some operation
            select {
                case out <- v:
                case <-ctx.Done():
                    return
            }
        }
    }()
    return out
}
```

在设计管道时，有一些通用规则应该遵循：

+   中间阶段将接收一个入站通道并返回另一个。

+   生产者不会接收任何通道，但会返回一个。

+   消费者将接收一个通道而不返回一个。

+   每个阶段在创建时都会关闭通道，当它发送完消息时。

+   每个阶段应该保持从输入通道接收，直到它关闭。

让我们创建一个简单的管道，使用特定字符串从读取器中过滤行并打印过滤后的行，突出显示搜索字符串。我们可以从第一个阶段开始 - 源 - 它在签名中不会接收任何通道，但会使用读取器扫描行。我们为了对早期退出请求做出反应（上下文取消）和使用`bufio`扫描器逐行读取。以下代码显示了这一点：

```go
func SourceLine(ctx context.Context, r io.ReadCloser) <-chan string {
    ch := make(chan string)
    go func() {
        defer func() { r.Close(); close(ch) }()
        s := bufio.NewScanner(r)
        for s.Scan() {
            select {
            case <-ctx.Done():
                return
            case ch <- s.Text():
            }
        }
    }()
    return ch
}
```

我们可以将剩余的操作分为两个阶段：过滤阶段和写入阶段。过滤阶段将简单地从源通道过滤到输出通道。我们仍然传递上下文，以避免在上下文已经完成的情况下发送额外的数据。这是文本过滤的实现：

```go
func TextFilter(ctx context.Context, src <-chan string, filter string) <-chan string {
    ch := make(chan string)
    go func() {
        defer close(ch)
        for v := range src {
            if !strings.Contains(v, filter) {
                continue
            }
            select {
            case <-ctx.Done():
                return
            case ch <- v:
            }
        }
    }()
    return ch
}
```

最后，我们有最终阶段，消费者，它将在写入器中打印输出，并且还将使用上下文进行早期退出：

```go
func Printer(ctx context.Context, src <-chan string, color int, highlight string, w io.Writer) {
    const close = "\x1b[39m"
    open := fmt.Sprintf("\x1b[%dm", color)
    for {
        select {
        case <-ctx.Done():
            return
        case v, ok := <-src:
            if !ok {
                return
            }
            i := strings.Index(v, highlight)
            if i == -1 {
                panic(v)
            }
            fmt.Fprint(w, v[:i], open, highlight, close, v[i+len(highlight):], "\n")
        }
    }
}
```

使用这个函数的方式如下：

```go
func main() {
    var search string
    ...
    ctx := context.Background()
    src := SourceLine(ctx, ioutil.NopCloser(strings.NewReader(sometext)))
    filter := TextFilter(ctx, src, search)
    Printer(ctx, filter, 31, search, os.Stdout)
}
```

通过这种方法，我们学会了如何将复杂的操作分解为由阶段执行的简单任务，并使用通道连接。

# 复用和解复用

现在我们熟悉了管道和阶段，我们可以介绍两个新概念：

+   **复用（多路复用）或扇出**：从一个通道接收并发送到多个通道

+   **解复用（解多路复用）或扇入**：从多个通道接收并通过一个通道发送

这种模式非常常见，可以让我们以不同的方式利用并发的力量。最明显的方式是从比其后续步骤更快的通道中分发数据，并创建多个此类步骤的实例来弥补速度差异。

# 扇出

复用的实现非常简单。同一个通道需要传递给不同的阶段，以便每个阶段都从中读取。

每个 goroutine 在运行时调度期间竞争资源，因此如果我们想保留更多的资源，我们可以为管道的某个阶段或应用程序中的某个操作使用多个 goroutine。

我们可以创建一个小应用程序，使用这种方法统计出现在一段文本中的单词的次数。让我们创建一个初始的生产者阶段，从写入器中读取并返回该行的单词切片：

```go
func SourceLineWords(ctx context.Context, r io.ReadCloser) <-chan []string {
    ch := make(chan []string)
    go func() {
        defer func() { r.Close(); close(ch) }()
        b := bytes.Buffer{}
        s := bufio.NewScanner(r)
        for s.Scan() {
            b.Reset()
            b.Write(s.Bytes())
            words := []string{}
            w := bufio.NewScanner(&b)
            w.Split(bufio.ScanWords)
            for w.Scan() {
                words = append(words, w.Text())
            }
            select {
            case <-ctx.Done():
                return
            case ch <- words:
            }
        }
    }()
    return ch
}
```

现在我们可以定义另一个阶段，用于计算这些单词的出现次数。我们将使用这个阶段进行扇出：

```go
func WordOccurrence(ctx context.Context, src <-chan []string) <-chan map[string]int {
    ch := make(chan map[string]int)
    go func() {
        defer close(ch)
        for v := range src {
            count := make(map[string]int)
            for _, s := range v {
                count[s]++
            }
            select {
            case <-ctx.Done():
                return
            case ch <- count:
            }
        }
    }()
    return ch
}
```

为了将第一阶段用作第二阶段的多个实例的来源，我们只需要使用相同的输入通道创建多个计数阶段：

```go
ctx, canc := context.WithCancel(context.Background())
defer canc()
src := SourceLineWords(ctx,   
    ioutil.NopCloser(strings.NewReader(cantoUno)))
count1, count2 := WordOccurrence(ctx, src), WordOccurrence(ctx, src)
```

# 扇入

Demuxing 有点复杂，因为我们不需要在一个 goroutine 中盲目地接收数据，而是需要同步一系列通道。避免竞争条件的一个好方法是创建另一个通道，所有来自各种输入通道的数据都将被接收到。我们还需要确保一旦所有通道都完成，这个合并通道就会关闭。我们还必须记住，如果上下文被取消，通道将被关闭。我们在这里使用`sync.Waitgroup`等待所有通道完成：

```go
wg := sync.WaitGroup{}
merge := make(chan map[string]int)
wg.Add(len(src))
go func() {
    wg.Wait()
    close(merge)
}()
```

问题在于我们有两种可能的触发器来关闭通道：常规传输结束和上下文取消。

我们必须确保如果上下文结束，不会向输出通道发送任何消息。在这里，我们正在从输入通道收集值并将它们发送到合并通道，但前提是上下文没有完成。我们这样做是为了避免将发送操作发送到关闭的通道，这将使我们的应用程序发生恐慌：

```go
for _, ch := range src {
    go func(ch <-chan map[string]int) {
        defer wg.Done()
        for v := range ch {
            select {
            case <-ctx.Done():    
                return
            case merge <- v:
            }
        }
    }(ch)
}
```

最后，我们可以专注于使用合并通道执行我们的最终字数的最后一个操作：

```go
count := make(map[string]int)
for {
    select {
    case <-ctx.Done():
        return count
    case c, ok := <-merge:
        if !ok {
            return count
        }
        for k, v := range c {
            count[k] += v
        }
    }
}
```

应用程序的`main`函数，在添加扇入后，将如下所示：

```go
func main() {
    ctx, canc := context.WithCancel(context.Background())
    defer canc()
    src := SourceLineWords(ctx, ioutil.NopCloser(strings.NewReader(cantoUno)))
    count1, count2 := WordOccurrence(ctx, src), WordOccurrence(ctx, src)
    final := MergeCounts(ctx, count1, count2)
    fmt.Println(final)
}
```

我们可以看到，扇入是应用程序最复杂和关键的部分。让我们回顾一下帮助构建一个没有恐慌或死锁的扇入函数的决定：

+   使用合并通道从各种输入中收集值。

+   使用`sync.WaitGroup`，计数器等于输入通道的数量。

+   在一个单独的 goroutine 中使用它，并等待它关闭通道。

+   对于每个输入通道，创建一个将值传输到合并通道的 goroutine。

+   确保只有在上下文没有完成的情况下才发送记录。

+   在退出这样的 goroutine 之前，使用等待组的`done`函数。

遵循上述步骤将允许我们使用简单的`range`从合并通道中获取值。在我们的示例中，我们还检查上下文是否完成，然后才从通道接收，以便允许 goroutine 提前退出。

# 生产者和消费者

通道允许我们轻松处理多个消费者从一个生产者接收数据的情况，反之亦然。

与单个生产者和一个消费者的情况一样，我们已经看到，这是非常直接的：

```go
func main() {
    // one producer
    var ch = make(chan int)
    go func() {
        for i := 0; i < 100; i++ {
            ch <- i
        }
        close(ch)
    }()
    // one consumer
    var done = make(chan struct{})
    go func() {
        for i := range ch {
            fmt.Println(i)
        }
        close(done)
    }()
    <-done
}
```

完整的示例在这里：[`play.golang.org/p/hNgehu62kjv`](https://play.golang.org/p/hNgehu62kjv)。

# 多个生产者（N * 1）

使用等待组可以轻松处理多个生产者或消费者的情况。在多个生产者的情况下，所有的 goroutine 都将共享同一个通道：

```go
// three producer
var ch = make(chan string)
wg := sync.WaitGroup{}
wg.Add(3)
for i := 0; i < 3; i++ {
    go func(n int) {
        for i := 0; i < 100; i++ {
            ch <- fmt.Sprintln(n, i)
        }
        wg.Done()
    }(i)
}
go func() {
    wg.Wait()
    close(ch)
}()
```

完整的示例在这里：[`play.golang.org/p/4DqWKntl6sS`](https://play.golang.org/p/4DqWKntl6sS)。

他们将使用`sync.WaitGroup`等待每个生产者完成后关闭通道。

# 多个消费者（1 * M）

相同的推理适用于多个消费者-它们都在不同的 goroutine 中从同一个通道接收：

```go
func main() {
    // three consumers
    wg := sync.WaitGroup{}
    wg.Add(3)
    var ch = make(chan string)

    for i := 0; i < 3; i++ {
        go func(n int) {
            for i := range ch {
                fmt.Println(n, i)
            }
            wg.Done()
        }(i)
    }

    // one producer
    go func() {
        for i := 0; i < 10; i++ {
            ch <- fmt.Sprintln("prod-", i)
        }
        close(ch)
    }()

    wg.Wait()
}
```

完整的示例在这里：[`play.golang.org/p/_SWtw54ITFn`](https://play.golang.org/p/_SWtw54ITFn)。

在这种情况下，`sync.WaitGroup`用于等待应用程序结束。

# 多个消费者和生产者（N*M）

最后的情况是我们有任意数量的生产者（`N`）和另一个任意数量的消费者（`M`）。

在这种情况下，我们需要两个等待组：一个用于生产者，另一个用于消费者：

```go
const (
    N = 3
    M = 5
)
wg1 := sync.WaitGroup{}
wg1.Add(N)
wg2 := sync.WaitGroup{}
wg2.Add(M)
var ch = make(chan string)
```

接下来是一系列生产者和消费者，每个都在自己的 goroutine 中：

```go
for i := 0; i < N; i++ {
    go func(n int) {
        for i := 0; i < 10; i++ {
            ch <- fmt.Sprintf("src-%d[%d]", n, i)
        }
        wg1.Done()
    }(i)
}

for i := 0; i < M; i++ {
    go func(n int) {
        for i := range ch {
            fmt.Printf("cons-%d, msg %q\n", n, i)
        }
        wg2.Done()
    }(i)
}
```

最后一步是等待`WaitGroup`生产者完成工作，以关闭通道。

然后，我们可以等待消费者通道，让所有消息都被消费者处理：

```go
wg1.Wait()
close(ch)
wg2.Wait()
```

# 其他模式

到目前为止，我们已经看过了可以使用的最常见的并发模式。现在，我们将专注于一些不太常见但值得一提的模式。

# 错误组

`sync.WaitGroup`的强大之处在于它允许我们等待同时运行的 goroutines 完成它们的工作。我们已经看过了如何共享上下文可以让我们在正确使用时为 goroutines 提供早期退出。第一个并发操作，比如从通道发送或接收，位于`select`块中，与上下文完成通道一起：

```go
func main() {
    ctx, canc := context.WithTimeout(context.Background(), time.Second)
    defer canc()
    wg := sync.WaitGroup{}
    wg.Add(10)
    var ch = make(chan int)
    for i := 0; i < 10; i++ {
        go func(ctx context.Context, i int) {
            defer wg.Done()
            d := time.Duration(rand.Intn(2000)) * time.Millisecond
            time.Sleep(d)
            select {
            case <-ctx.Done():
                fmt.Println(i, "early exit after", d)
                return
            case ch <- i:
                fmt.Println(i, "normal exit after", d)
            }
        }(ctx, i)
    }
    go func() {
        wg.Wait()
        close(ch)
    }()
    for range ch {
    }
}
```

实验性的`golang.org/x/sync/errgroup`包提供了对这种情况的改进。

内置的 goroutines 始终是`func()`类型，但这个包允许我们并发执行`func() error`并返回从各种 goroutines 接收到的第一个错误。

在启动更多 goroutines 并接收第一个错误的情况下，这非常有用。`errgroup.Group`类型可以用作零值，其`Do`方法以`func() error`作为参数并并发启动函数。

`Wait`方法要么等待所有函数成功完成并返回`nil`，要么返回来自任何函数的第一个错误。

让我们创建一个定义 URL 访问者的示例，即一个获取 URL 字符串并返回`func() error`的函数，用于发起调用：

```go
func visitor(url string) func() error {
    return func() (err error) {
        s := time.Now()
        defer func() {
            log.Println(url, time.Since(s), err)
        }()
        var resp *http.Response
        if resp, err = http.Get(url); err != nil {
            return
        }
        return resp.Body.Close()
    }
}
```

我们可以直接使用`Go`方法并等待。这将返回由无效 URL 引起的错误：

```go
func main() {
    eg := errgroup.Group{}
    var urlList = []string{
        "http://www.golang.org/",
        "http://invalidwebsite.hey/",
        "http://www.google.com/",
    }
    for _, url := range urlList {
        eg.Go(visitor(url))
    }
    if err := eg.Wait(); err != nil {
        log.Fatalln("Error:", err)
    }
}
```

错误组还允许我们使用`WithContext`函数创建一个组以及上下文。当收到第一个错误时，此上下文将被取消。上下文的取消使`Wait`方法能够立即返回，但也允许在函数的 goroutines 中进行早期退出。

我们可以创建一个类似的`func() error`创建者，它会将值发送到通道直到上下文关闭。我们将引入一个小概率（1%）引发错误：

```go
func sender(ctx context.Context, ch chan<- string, n int) func() error {
    return func() (err error) {
        for i := 0; ; i++ {
            if rand.Intn(100) == 42 {
                return errors.New("the answer")
            }
            select {
            case ch <- fmt.Sprintf("[%d]%d", n, i):
            case <-ctx.Done():
                return nil
            }
        }
    }
}
```

我们将使用专用函数生成一个错误组和一个上下文，并使用它来启动函数的多个实例。在等待组时，我们将在一个单独的 goroutine 中接收到它。等待结束后，我们将确保没有更多的值被发送到通道（这将导致恐慌），通过额外等待一秒钟：

```go
func main() {
    eg, ctx := errgroup.WithContext(context.Background())
    ch := make(chan string)
    for i := 0; i < 10; i++ {
        eg.Go(sender(ctx, ch, i))
    }
    go func() {
        for s := range ch {
            log.Println(s)
        }
    }()
    if err := eg.Wait(); err != nil {
        log.Println("Error:", err)
    }
    close(ch)
    log.Println("waiting...")
    time.Sleep(time.Second)
}
```

正如预期的那样，由于上下文中的`select`语句，应用程序运行顺利，不会发生恐慌。

# 泄漏桶

我们在前几章中看到了如何使用 ticker 构建速率限制器：通过使用`time.Ticker`强制客户端等待轮到自己被服务。还有另一种对服务和库进行速率限制的方法，称为**泄漏桶**。这个名字让人联想到一个有几个孔的桶。如果你在往里面加水，就要小心不要把太多水放进去，否则它会溢出。在添加更多水之前，你需要等待水位下降 - 这种速度取决于桶的大小和孔的数量。通过以下类比，我们可以很容易地理解这种并发模式的作用：

+   通过孔洞流出的水代表已完成的请求。

+   从桶中溢出的水代表被丢弃的请求。

桶将由两个属性定义：

+   **速率**：如果请求频率较低，则每个时间段的理想请求量。

+   **容量**：在资源暂时变得无响应之前，可以同时完成的请求数量。

桶具有最大容量，因此当请求的频率高于指定的速率时，该容量开始下降，就像当您放入太多水时，桶开始溢出一样。如果频率为零或低于速率，则桶将缓慢恢复其容量，因此水将被缓慢排出。

漏桶的数据结构将具有容量和可用请求的计数器。该计数器在创建时将与容量相同，并且每次执行请求时都会减少。速率指定了状态需要多久重置到容量的频率：

```go
type bucket struct {
    capacity uint64
    status uint64
}
```

创建新的桶时，我们还应该注意状态重置。我们可以使用 goroutine 和上下文来正确终止它。我们可以使用速率创建一个 ticker，然后使用这些 ticks 来重置状态。我们需要使用 atomic 包来确保它是线程安全的：

```go
func newBucket(ctx context.Context, cap uint64, rate time.Duration) *bucket {
    b := bucket{capacity: cap, status: cap}
    go func() {
        t := time.NewTicker(rate)
        for {
            select {
            case <-t.C:
                atomic.StoreUint64(&b.status, b.capacity)
            case <-ctx.Done():
                t.Stop()
                return
            }
        }
    }()
    return &b
}
```

当我们向桶中添加内容时，我们可以检查状态并相应地采取行动：

+   如果状态为`0`，我们无法添加任何内容。

+   如果要添加的数量高于可用性，我们将添加我们可以的内容。

+   否则，我们将添加完整的数量：

```go
func (b *bucket) Add(n uint64) uint64 {
    for {
        r := atomic.LoadUint64(&b.status)
        if r == 0 {
            return 0
        }
        if n > r {
            n = r
        }
        if !atomic.CompareAndSwapUint64(&b.status, r, r-n) {
            continue
        }
        return n
    }
}
```

我们使用循环尝试原子交换操作，直到成功为止，以确保我们在进行**比较和交换**（**CAS**）时得到的内容不会在进行**加载**操作时发生变化。

桶可以用于尝试向桶中添加随机数量并记录其结果的客户端：

```go
type client struct {
    name string
    max int
    b *bucket
    sleep time.Duration
}

func (c client) Run(ctx context.Context, start time.Time) {
    for {
        select {
        case <-ctx.Done():
            return
        default:
            n := 1 + rand.Intn(c.max-1)
            time.Sleep(c.sleep)
            e := time.Since(start).Seconds()
            a := c.b.Add(uint64(n))
            log.Printf("%s tries to take %d after %.02fs, takes  
                %d", c.name, n, e, a)
        }
    }
}
```

我们可以同时使用更多客户端，以便并发访问资源将产生以下结果：

+   一些 goroutine 将向桶中添加他们期望的内容。

+   一个 goroutine 最终将通过添加与剩余容量相等的数量来填充桶，即使他们试图添加的数量更高。

+   其他 goroutine 在容量重置之前将无法向桶中添加内容：

```go
func main() {
    ctx, canc := context.WithTimeout(context.Background(), time.Second)
    defer canc()
    start := time.Now()
    b := newBucket(ctx, 10, time.Second/5)
    t := time.Second / 10
    for i := 0; i < 5; i++ {
        c := client{
            name: fmt.Sprint(i),
            b: b,
            sleep: t,
            max: 5,
        }
        go c.Run(ctx, start)
    }
    <-ctx.Done()
}
```

# 排序

在具有多个 goroutine 的并发场景中，我们可能需要在 goroutine 之间进行同步，例如在每个 goroutine 发送后需要等待轮次的情况下。

这种情况的一个用例可能是一个基于轮次的应用程序，其中不同的 goroutine 正在向同一个通道发送消息，并且每个 goroutine 都必须等到所有其他 goroutine 完成后才能再次发送消息。

可以使用主 goroutine 和发送者之间的私有通道来获得此场景的非常简单的实现。我们可以定义一个非常简单的结构，其中包含消息和`Wait`通道。它将有两种方法-一种用于标记交易已完成，另一种等待这样的信号-当它在下面使用通道时。以下方法显示了这一点：

```go
type msg struct {
    value string
    done chan struct{}
}

func (m *msg) Wait() {
    <-m.done
}

func (m *msg) Done() {
    m.done <- struct{}{}
}
```

我们可以使用生成器创建消息源。我们可以使用`send`操作进行随机延迟。每次发送后，我们等待通过调用`Done`方法获得的信号。我们始终使用上下文来确保一切都不会泄漏：

```go
func send(ctx context.Context, v string) <-chan msg {
    ch := make(chan msg)
    go func() {
        done := make(chan struct{})
        for i := 0; ; i++ {
            time.Sleep(time.Duration(float64(time.Second/2) * rand.Float64()))
            m := msg{fmt.Sprintf("%s msg-%d", v, i), done}
            select {
            case <-ctx.Done():
                close(ch)
                return
            case ch <- m:
                m.Wait()
            }
        }
    }()
    return ch
}
```

我们可以使用 fan-in 将所有通道放入一个单一的通道中：

```go

func merge(ctx context.Context, sources ...<-chan msg) <-chan msg {
    ch := make(chan msg)
    go func() {
        <-ctx.Done()
        close(ch)
    }()
    for i := range sources {
        go func(i int) {
            for {
                select {
                case v := <-sources[i]:
                    select {
                    case <-ctx.Done():
                        return
                    case ch <- v:
                    }
                }
            }
        }(i)
    }
    return ch
}
```

主应用程序将从合并的通道接收，直到它关闭。当它从每个通道接收到一个消息时，通道将被阻塞，等待主 goroutine 调用`Done`方法信号。

这种特定的配置将允许主 goroutine 仅从每个通道接收一个消息。当消息计数达到 goroutine 数量时，我们可以从主 goroutine 调用`Done`并重置列表，以便其他 goroutine 将被解锁并能够再次发送消息：

```go
func main() {
    ctx, canc := context.WithTimeout(context.Background(), time.Second)
    defer canc()
    sources := make([]<-chan msg, 5)
    for i := range sources {
        sources[i] = send(ctx, fmt.Sprint("src-", i))
    }
    msgs := make([]msg, 0, len(sources))
    start := time.Now()
    for v := range merge(ctx, sources...) {
        msgs = append(msgs, v)
        log.Println(v.value, time.Since(start))
        if len(msgs) == len(sources) {
            log.Println("*** done ***")
            for _, m := range msgs {
                m.Done()
            }
            msgs = msgs[:0]
            start = time.Now()
        }
    }
}
```

运行应用程序将导致所有 goroutine 向主 goroutine 发送一条消息。每个 goroutine 都将等待其他人发送消息。然后，他们将开始再次发送消息。这导致消息按轮次发送，正如预期的那样。

# 总结

在本章中，我们研究了一些特定的并发模式，用于我们的应用程序。我们了解到生成器是返回通道的函数，并且还向这些通道提供数据，并在没有更多数据时关闭它们。我们还看到我们可以使用上下文来允许生成器提前退出。

接下来，我们专注于管道，这是使用通道进行通信的执行阶段。它们可以是源，不需要任何输入；目的地，不返回通道；或者中间的，接收通道作为输入并返回一个作为输出。

另一个模式是多路复用和分解复用，它包括将一个通道传播到不同的 goroutine，并将多个通道合并成一个。它通常被称为*扇出扇入*，它允许我们在一组数据上并发执行不同的操作。

最后，我们学习了如何实现一个更好的速率限制器称为**漏桶**，它限制了在特定时间内的请求数。我们还看了顺序模式，它使用私有通道向所有发送 goroutine 发出信号，告诉它们何时可以再次发送数据。

在下一章中，我们将介绍在*顺序*部分中提出的两个额外主题中的第一个。在这里，我们将演示如何使用反射来构建适应任何用户提供的类型的通用代码。

# 问题

1.  生成器是什么？它的责任是什么？

1.  你如何描述一个管道？

1.  什么类型的阶段获得一个通道并返回一个通道？

1.  扇入和扇出之间有什么区别？


# 第五部分：使用反射和 CGO 的指南

本节重点介绍两种非常有争议的工具——反射，它允许创建通用代码，但在性能方面代价很大；以及 CGO，它允许在 Go 应用程序中使用 C 代码，但使得调试和控制应用程序变得更加复杂。

本节包括以下章节：

+   第十五章，*使用反射*

+   第十六章，*使用 CGO*


# 第十五章：使用反射

本章是关于**反射**，这是一种工具，允许应用程序检查自己的代码，克服 Go 静态类型和泛型缺乏所施加的一些限制。例如，这对于生成能够处理其接收到的任何类型输入的包可能非常有帮助。

本章将涵盖以下主题：

+   理解接口和类型断言

+   了解与基本类型的交互

+   使用复杂类型进行反射

+   评估反射的成本

+   学习反射使用的最佳实践

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅第三章，*Go 概述*。

# 什么是反射？

反射是一种非常强大的功能，允许**元编程**，即应用程序检查自身结构的能力。它非常有用，可以在运行时分析应用程序中的类型，并且在许多编码包中使用，例如 JSON 和 XML。

# 类型断言

我们在[第三章](https://cdp.packtpub.com/hands_on_systems_programming_with_go/wp-admin/post.php?post=38&action=edit#post_26)，*Go 概述*中简要提到了类型断言的工作原理。类型断言是一种操作，允许我们从接口到具体类型以及反之进行转换。它采用以下形式：

```go
# unsafe assertion
v := SomeVar.(SomeType)

# safe assertion
v, ok := SomeVar.(SomeType)
```

第一个版本是不安全的，它将一个值分配给一个变量。

将断言用作函数的参数也被视为不安全。如果断言错误，此类操作将引发**panic**：

```go
func main() {
    var a interface{} = "hello"
    fmt.Println(a.(string)) // ok
    fmt.Println(a.(int))    // panics!
}
```

完整示例可在此处找到：[`play.golang.org/p/hNN87SuprGR`](https://play.golang.org/p/hNN87SuprGR)。

第二个版本使用布尔值作为第二个值，并且它将显示操作的成功。如果断言不可能，第一个值将始终是断言类型的零值：

```go
func main() {
    var a interface{} = "hello"
    s, ok := a.(string) // true
    fmt.Println(s, ok)
    i, ok := a.(int) // false
    fmt.Println(i, ok)
}
```

完整示例可在此处找到：[`play.golang.org/p/BIba2ywkNF_j`](https://play.golang.org/p/BIba2ywkNF_j)。

# 接口断言

断言也可以从一个接口到另一个接口进行。想象一下有两个不同的接口：

```go
type Fooer interface {
    Foo()
}

type Barer interface {
    Bar()
}
```

让我们定义一个实现其中一个的类型，另一个实现两者的类型：

```go
type A int

func (A) Foo() {}

type B int

func (B) Bar() {}
func (B) Foo() {}
```

如果我们为第一个接口定义一个新变量，只有在底层值具有实现两者的类型时，对第二个的断言才会成功；否则，它将失败：

```go
func main() {
    var a Fooer 

    a = A(0)
    v, ok := a.(Barer)
    fmt.Println(v, ok)

    a = B(0) 
    v, ok = a.(Barer)
    fmt.Println(v, ok)
}
```

完整示例可在此处找到：[`play.golang.org/p/bX2rnw5pRXJ`](https://play.golang.org/p/bX2rnw5pRXJ)。

一个使用场景可能是拥有`io.Reader`接口，检查它是否也是`io.Closer`接口，并在需要时使用`ioutil.NopCloser`函数（返回`io.ReadCloser`接口）进行包装：

```go
func Closer(r io.Reader) io.ReadCloser {
    if rc, ok := r.(io.ReadCloser); ok {
        return rc
    }
    return ioutil.NopCloser(r)
}

func main() {
    log.Printf("%T", Closer(&bytes.Buffer{}))
    log.Printf("%T", Closer(&os.File{}))
}
```

完整示例可在此处找到：[`play.golang.org/p/hUEsDYHFE7i`](https://play.golang.org/p/hUEsDYHFE7i)。

在跳转到反射之前，接口有一个重要的方面需要强调——它的表示始终是一个元组接口值，其中值是一个具体类型，不能是另一个接口。

# 理解基本机制

`reflection`包允许您从任何`interface{}`变量中提取类型和值。可以使用以下方法完成：

+   使用`reflection.TypeOf`返回接口的类型到`reflection.Type`变量。

+   `reflection.ValueOf`函数使用`reflection.Value`变量返回接口的值。

# 值和类型方法

`reflect.Value`类型还携带可以使用`Type`方法检索的类型信息：

```go
func main() {
    var a interface{} = int64(23)
    fmt.Println(reflect.TypeOf(a).String())
    // int64
    fmt.Println(reflect.ValueOf(a).String())
    // <int64 Value>
    fmt.Println(reflect.ValueOf(a).Type().String())
    // int64
}
```

完整示例可在此处找到：[`play.golang.org/p/tmYuMc4AF1T`](https://play.golang.org/p/tmYuMc4AF1T)。

# 种类

`reflect.Type`的另一个重要属性是`Kind`，它是基本类型和通用复杂类型的枚举。`reflect.Kind`和`reflect.Type`之间的主要关系是，前者表示后者的内存表示。

对于内置类型，`Kind`和`Type`是相同的，但对于自定义类型，它们将不同 - `Type`值将是预期的值，但`Kind`值将是自定义类型定义的内置类型之一：

```go
func main() {
    var a interface{}

    a = "" // built in string
    t := reflect.TypeOf(a)
    fmt.Println(t.String(), t.Kind())

    type A string // custom type
    a = A("")
    t = reflect.TypeOf(a)
    fmt.Println(t.String(), t.Kind())
}
```

完整示例在此处可用：[`play.golang.org/p/qjiouk88INn`](https://play.golang.org/p/qjiouk88INn)。

对于复合类型，它将反映出主要类型而不是底层类型。这意味着指向结构或整数的指针是相同类型，`reflect.Pointer`：

```go
func main() {
    var a interface{}

    a = new(int) // int pointer
    t := reflect.TypeOf(a)
    fmt.Println(t.String(), t.Kind())

    a = new(struct{}) // struct pointer
    t = reflect.TypeOf(a)
    fmt.Println(t.String(), t.Kind())
}
```

完整示例在此处可用：[`play.golang.org/p/-uJjZvTuzVf`](https://play.golang.org/p/-uJjZvTuzVf)。

相同的推理适用于所有其他复合类型，例如数组，切片，映射和通道。

# 值到接口

就像我们可以从任何`interface{}`值获取`reflect.Value`一样，我们也可以执行相反的操作，并从`reflect.Value`获取`interface{}`。这是使用反射值的`Interface`方法完成的，并且如果需要，可以转换为具体类型。如果感兴趣的方法或函数接受空接口，例如`json.Marshal`或`fmt.Println`，则返回的值可以直接传递，而无需任何转换：

```go
func main() {
    var a interface{} = int(12)
    v := reflect.ValueOf(a)
    fmt.Println(v.String())
    fmt.Printf("%v", v.Interface())
}
```

完整示例在此处可用：[`play.golang.org/p/1942Dhm5sap`](https://play.golang.org/p/1942Dhm5sap)。

# 操纵值

将值转换为其反射形式，然后再转回值，如果值本身无法更改，这是没有什么用的。这就是为什么我们的下一步是看看如何使用`reflection`包来更改它们。

# 更改值

`reflect.Value`类型有一系列方法，允许您更改底层值：

+   `Set`: 使用另一个`reflect.Value`

+   `SetBool`: 布尔值

+   `SetBytes`: 字节切片

+   `SetComplex`: 任何复杂类型

+   `SetFloat`: 任何浮点类型

+   `SetInt`: 任何有符号整数类型

+   `SetPointer`: 指针

+   `SetString`: 字符串

+   `SetUint`: 任何无符号整数

为了设置一个值，它需要是可编辑的，这发生在特定条件下。为了验证这一点，有一个方法`CanSet`，如果一个值可以被更改，则返回`true`。如果值无法更改，但仍然调用了`Set`方法，应用程序将会引发恐慌：

```go
func main() {
    var a = int64(12)
    v := reflect.ValueOf(a)
    fmt.Println(v.String(), v.CanSet())
    v.SetInt(24)
}
```

完整示例在此处可用：[`play.golang.org/p/hKn8qNtn0gN`](https://play.golang.org/p/hKn8qNtn0gN)。

为了进行更改，值需要是可寻址的。如果可以修改对象保存的实际存储位置，则值是可寻址的。当使用基本内置类型（例如`string`）创建新值时，传递给函数的是`interface{}`，它包含字符串的副本。

更改此副本将导致副本的变化，而不会影响原始变量。这将非常令人困惑，并且会使反射等实用工具的使用变得更加困难。这就是为什么，`reflect`包会引发恐慌 - 这是一个设计选择。这就解释了为什么最后一个示例会引发恐慌。

我们可以使用要更改的值的指针创建`reflect.Value`，并使用`Elem`方法访问该值。这将给我们一个可寻址的值，因为我们复制了指针而不是值，所以反射的值仍然是变量的指针：

```go
func main() {
    var a = int64(12)
    v := reflect.ValueOf(&a)
    fmt.Println(v.String(), v.CanSet())
    e := v.Elem()
    fmt.Println(e.String(), e.CanSet())
    e.SetInt(24)
    fmt.Println(a)
}
```

完整示例在此处可用：[`play.golang.org/p/-X5JsBrlr4Q`](https://play.golang.org/p/-X5JsBrlr4Q)。

# 创建新值

`reflect`包还允许我们使用类型创建新值。有几个函数允许我们创建一个值：

+   `MakeChan`创建一个新的通道值

+   `MakeFunc`创建一个新的函数值

+   `MakeMap`和`MakeMapWithSize`创建一个新的映射值

+   `MakeSlice`创建一个新的切片值

+   `New`创建一个指向该类型的新指针

+   `NewAt` 使用所选地址创建类型的新指针

+   `Zero` 创建所选类型的零值

以下代码显示了如何以几种不同的方式创建新值：

```go
func main() {
    t := reflect.TypeOf(int64(100))
    // zero value
    fmt.Printf("%#v\n", reflect.Zero(t))
    // pointer to int
    fmt.Printf("%#v\n", reflect.New(t))
}
```

完整的示例在这里：[`play.golang.org/p/wCTILSK1F1C`](https://play.golang.org/p/wCTILSK1F1C)。

# 处理复杂类型

在了解如何处理反射基础知识之后，我们现在将看到如何使用反射处理结构和地图等复杂数据类型。

# 数据结构

为了可更改性，结构与基本类型的工作方式完全相同； 我们需要获取指针的反射，然后访问其元素以能够更改值，因为直接使用结构会产生其副本，并且在更改值时会出现恐慌。

我们可以使用 `Set` 方法替换整个结构的值，然后获取新值的反射：

```go
func main() {
    type X struct {
        A, B int
        c string
    }
    var a = X{10, 100, "apple"}
    fmt.Println(a)
    e := reflect.ValueOf(&a).Elem()
    fmt.Println(e.String(), e.CanSet())
    e.Set(reflect.ValueOf(X{1, 2, "banana"}))
    fmt.Println(a)
}
```

完整的示例在这里：[`play.golang.org/p/mjb3gJw5CeA`](https://play.golang.org/p/mjb3gJw5CeA)。

# 更改字段

也可以使用 `Field` 方法修改单个字段：

+   `Field` 使用其索引返回一个字段

+   `FieldByIndex` 使用一系列索引返回嵌套字段

+   `FieldByName` 使用其名称返回一个字段

+   `FieldByNameFunc` 使用 `func(string) bool` 返回一个字段

让我们定义一个结构来更改字段的值，使用简单和复杂类型，至少有一个未导出的字段：

```go
type A struct {
    B
    x int
    Y int
    Z int
}

type B struct {
    F string
    G string
}
```

现在我们有了结构，我们可以尝试以不同的方式访问字段：

```go
func main() {
    var a A
    v := reflect.ValueOf(&a)
    func() {
        // trying to get fields from ptr panics
        defer func() {
            log.Println("panic:", recover())
        }()
        log.Printf("%s", v.Field(1).String())
    }()
    v = v.Elem()
    // changing fields by index
    for i := 0; i < 4; i++ {
        f := v.Field(i)
        if f.CanSet() && f.Type().Kind() == reflect.Int {
            f.SetInt(42)
        }
    }
    // changing nested fields by index
    v.FieldByIndex([]int{0, 1}).SetString("banana")

    // getting fields by name
    v.FieldByName("B").FieldByName("F").SetString("apple")

    log.Printf("%+v", a)
}
```

完整的示例在这里：[`play.golang.org/p/z5slFkIU5UE`](https://play.golang.org/p/z5slFkIU5UE)。

在处理 `reflect.Value` 和结构字段时，您得到的是其他值，无法与结构区分。 相反，当处理 `reflect.Type` 时，您获得一个 `reflect.StructField` 结构，它是另一种携带字段所有信息的类型。

# 使用标签

结构字段携带大量信息，从字段名称和索引到其标记：

```go
type StructField struct {
    Name string
    PkgPath string

    Type Type      // field type
    Tag StructTag  // field tag string
    Offset uintptr // offset within struct, in bytes
    Index []int    // index sequence for Type.FieldByIndex
    Anonymous bool // is an embedded field
}
```

可以使用 `reflect.Type` 方法获取 `reflect.StructField` 值：

+   `Field`

+   `FieldByName`

+   `FieldByIndex`

它们是由 `reflect.Value` 使用的相同方法，但它们返回不同的类型。 `NumField` 方法返回结构的字段总数，允许我们执行迭代：

```go
type Person struct {
    Name string `json:"name,omitempty" xml:"-"`
    Surname string `json:"surname,omitempty" xml:"-"`
}

func main() {
    v := reflect.ValueOf(Person{"Micheal", "Scott"})
    t := v.Type()
    fmt.Println("Type:", t)
    for i := 0; i < t.NumField(); i++ {
       fmt.Printf("%v: %v\n", t.Field(i).Name, v.Field(i))
    }
}
```

完整的示例在这里：[`play.golang.org/p/nkEADg77zFC`](https://play.golang.org/p/nkEADg77zFC)。

标签对于反射非常重要，因为它们可以存储有关字段的额外信息以及其他包如何与其交互的信息。 要向字段添加标签，需要在字段名称和类型之后插入一个字符串，该字符串应具有 `key:"value"` 结构。 一个字段可以在其标记中有多个元组，并且每对由空格分隔。 让我们看一个实际的例子：

```go
type A struct {
    Name    string `json:"name,omitempty" xml:"-"`
    Surname string `json:"surname,omitempty" xml:"-"`
}
```

该结构有两个字段，都带有标签，每个标签都有两对。 `Get` 方法返回特定键的值：

```go
func main() {
    t := reflect.TypeOf(A{})
    fmt.Println(t)
    for i := 0; i < t.NumField(); i++ {
        f := t.Field(i)
        fmt.Printf("%s JSON=%s XML=%s\n", f.Name, f.Tag.Get("json"), f.Tag.Get("xml"))
    }
}
```

完整的示例在这里：[`play.golang.org/p/P-Te8O1Hyyn`](https://play.golang.org/p/P-Te8O1Hyyn)。

# 地图和切片

您可以轻松使用反射来读取和操作地图和切片。 由于它们是编写应用程序的重要工具，让我们看看如何使用反射执行操作。

# 地图

`map` 类型允许您使用 `Key` 和 `Elem` 方法获取值和键的类型：

```go
func main() {
    maps := []interface{}{
        make(map[string]struct{}),
        make(map[int]rune),
        make(map[float64][]byte),
        make(map[int32]chan bool),
        make(map[[2]string]interface{}),
    }
    for _, m := range maps {
        t := reflect.TypeOf(m)
        fmt.Printf("%s k:%-10s v:%-10s\n", m, t.Key(), t.Elem())
    }
}
```

完整的示例在这里：[`play.golang.org/p/j__1jtgy-56`](https://play.golang.org/p/j__1jtgy-56)。

可以以正常访问映射的所有方式访问值：

+   通过键获取值

+   通过键的范围

+   通过值的范围

让我们看一个实际的例子：

```go
func main() {
    m := map[string]int64{
        "a": 10,
        "b": 20,
        "c": 100,
        "d": 42,
    }

    v := reflect.ValueOf(m)

    // access one field
    fmt.Println("a", v.MapIndex(reflect.ValueOf("a")))
    fmt.Println()

    // range keys
    for _, k := range v.MapKeys() {
        fmt.Println(k, v.MapIndex(k))
    }
    fmt.Println()

    // range keys and values
    i := v.MapRange()
    for i.Next() {
        fmt.Println(i.Key(), i.Value())
    }
}
```

请注意，我们无需传递指向地图的指针以使其可寻址，因为地图已经是指针。

每种方法都非常直接，并取决于您对映射的访问类型。设置值也是可能的，并且应该始终是可能的，因为映射是通过引用传递的。以下代码片段显示了一个实际示例：

```go
func main() {
    m := map[string]int64{}
    v := reflect.ValueOf(m)

    // setting one field
    v.SetMapIndex(reflect.ValueOf("key"), reflect.ValueOf(int64(1000)))

    fmt.Println(m)
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/JxK_8VPoWU0`](https://play.golang.org/p/JxK_8VPoWU0)。

还可以使用此方法取消设置变量，就像我们在调用`delete`函数时使用`reflect.Value`的零值作为第二个参数一样：

```go
func main() {
    m := map[string]int64{"a": 10}
    fmt.Println(m, len(m))

    v := reflect.ValueOf(m)

    // deleting field
    v.SetMapIndex(reflect.ValueOf("a"), reflect.Value{})

    fmt.Println(m, len(m))
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/4bPqfmaKzTC`](https://play.golang.org/p/4bPqfmaKzTC)。

输出将少一个字段，因为在`SetMapIndex`之后，映射的长度减少了。

# 切片

切片允许您使用`Len`方法获取其大小，并使用`Index`方法访问其元素。让我们在以下代码中看看它的运行情况：

```go
func main() {
    m := []int{10, 20, 100}
    v := reflect.ValueOf(m)

    for i := 0; i < v.Len(); i++ {
        fmt.Println(i, v.Index(i))
    }
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/ifq0O6bFIZc.`](https://play.golang.org/p/ifq0O6bFIZc)

由于始终可以获取切片元素的地址，因此也可以使用`reflect.Value`来更改切片中相应元素的内容：

```go
func main() {
    m := []int64{10, 20, 100}
    v := reflect.ValueOf(m)

    for i := 0; i < v.Len(); i++ {
        v.Index(i).SetInt(v.Index(i).Interface().(int64) * 2)
    }
    fmt.Println(m)
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/onuIvWyQ7GY`](https://play.golang.org/p/onuIvWyQ7GY)。

还可以使用`reflect`包将内容附加到切片。如果值是从切片的指针获得的，则此操作的结果也可以用于替换原始切片：

```go
func main() {
    var s = []int{1, 2}
    fmt.Println(s)

    v := reflect.ValueOf(s)
    // same as append(s, 3)
    v2 := reflect.Append(v, reflect.ValueOf(3))
    // s can't and does not change
    fmt.Println(v.CanSet(), v, v2)

    // using the pointer allows change
    v = reflect.ValueOf(&s).Elem()
    v.Set(v2)
    fmt.Println(v.CanSet(), v, v2)
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/2hXRg7Ih9wk`](https://play.golang.org/p/2hXRg7Ih9wk)。

# 函数

使用反射处理方法和函数可以收集有关特定条目签名的信息，并调用它。

# 分析函数

包中有一些`reflect.Type`的方法将返回有关函数的信息。这些方法如下：

+   `NumIn`：返回函数的输入参数数量

+   `In`：返回所选输入参数

+   `IsVariadic`：告诉您函数的最后一个参数是否是可变参数

+   `NumOut`：返回函数返回的输出值的数量

+   `Out`：返回选择输出的`Type`值

请注意，如果`reflect.Type`的类型不是`Func`，所有这些方法都会引发恐慌。我们可以通过定义一系列函数来测试这些方法：

```go
func Foo() {}

func Bar(a int, b string) {}

func Baz(a int, b string) (int, error) { return 0, nil }

func Qux(a int, b ...string) (int, error) { return 0, nil }
```

现在我们可以使用`reflect.Type`的方法来获取有关它们的信息：

```go
func main() {
    for _, f := range []interface{}{Foo, Bar, Baz, Qux} {
        t := reflect.TypeOf(f)
        name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
        in := make([]reflect.Type, t.NumIn())
        for i := range in {
            in[i] = t.In(i)
        }
        out := make([]reflect.Type, t.NumOut())
        for i := range out {
            out[i] = t.Out(i)
        }
        fmt.Printf("%q %v %v %v\n", name, in, out, t.IsVariadic())
    }
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/LAjjhw8Et60`](https://play.golang.org/p/LAjjhw8Et60)。

为了获取函数的名称，我们使用`runtime.FuncForPC`函数，它返回包含有关函数的运行时信息的`runtime.Func`，包括`name`、`file`和`line`。该函数以`uintptr`作为参数，可以通过函数的`reflect.Value`和其`Pointer`方法获得。

# 调用函数

虽然函数的类型显示了有关它的信息，但为了调用函数，我们需要使用它的值。

我们将向函数传递参数值列表，并获取函数调用返回的值：

```go
func main() {
    for _, f := range []interface{}{Foo, Bar, Baz, Qux} {
        v, t := reflect.ValueOf(f), reflect.TypeOf(f)
        name := runtime.FuncForPC(v.Pointer()).Name()
        in := make([]reflect.Value, t.NumIn())
        for i := range in {
            switch a := t.In(i); a.Kind() {
            case reflect.Int:
                in[i] = reflect.ValueOf(42)
            case reflect.String:
                in[i] = reflect.ValueOf("42")
            case reflect.Slice:
                switch a.Elem().Kind() {
                case reflect.Int:
                    in[i] = reflect.ValueOf(21)
                case reflect.String:
                    in[i] = reflect.ValueOf("21")
                }
            }
        }
        out := v.Call(in)
        fmt.Printf("%q %v%v\n", name, in, out)
    }
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/jPxO_G7YP2I`](https://play.golang.org/p/jPxO_G7YP2I)。

# 通道

反射允许我们创建通道，发送和接收数据，并且还可以使用`select`语句。

# 创建通道

可以通过`reflect.MakeChan`函数创建一个新的通道，该函数需要一个`reflect.Type`接口值和一个大小：

```go
func main() {
    t := reflect.ChanOf(reflect.BothDir, reflect.TypeOf(""))
    v := reflect.MakeChan(t, 0)
    fmt.Printf("%T\n", v.Interface())
}
```

一个完整的示例可以在这里找到：[`play.golang.org/p/7_RLtzjuTcz`](https://play.golang.org/p/7_RLtzjuTcz)。

# 发送、接收和关闭

`reflect.Value`类型提供了一些方法，必须与通道一起使用，`Send`和`Recv`用于发送和接收，`Close`用于关闭通道。让我们看一下这些函数和方法的一个示例用法：

```go
func main() {
    t := reflect.ChanOf(reflect.BothDir, reflect.TypeOf(""))
    v := reflect.MakeChan(t, 0)
    go func() {
        for i := 0; i < 10; i++ {
            v.Send(reflect.ValueOf(fmt.Sprintf("msg-%d", i)))
        }
        v.Close()
    }()
    for msg, ok := v.Recv(); ok; msg, ok = v.Recv() {
        fmt.Println(msg)
    }
}
```

这里有一个完整的示例：[`play.golang.org/p/Gp8JJmDbLIL`](https://play.golang.org/p/Gp8JJmDbLIL)。

# 选择语句

`select`语句可以使用`reflect.Select`函数执行。每个 case 由一个数据结构表示：

```go
type SelectCase struct {
    Dir  SelectDir // direction of case
    Chan Value     // channel to use (for send or receive)
    Send Value     // value to send (for send)
}
```

它包含操作的方向以及通道和值（用于发送操作）。方向可以是发送、接收或无（用于默认语句）：

```go
func main() {
    v := reflect.ValueOf(make(chan string, 1))
    fmt.Println("sending", v.TrySend(reflect.ValueOf("message"))) // true 1 1
    branches := []reflect.SelectCase{
        {Dir: reflect.SelectRecv, Chan: v, Send: reflect.Value{}},
        {Dir: reflect.SelectSend, Chan: v, Send: reflect.ValueOf("send")},
        {Dir: reflect.SelectDefault},
    }

    // send, receive and default
    i, recv, closed := reflect.Select(branches)
    fmt.Println("select", i, recv, closed)

    v.Close()
    // just default and receive
    i, _, closed = reflect.Select(branches[:2])
    fmt.Println("select", i, closed) // 1 false
}
```

这里有一个完整的示例：[`play.golang.org/p/_DgSYRIBkJA`](https://play.golang.org/p/_DgSYRIBkJA)。

# 反射反射

在讨论了反射在所有方面的工作原理之后，我们现在将专注于其缺点，即在标准库中使用它的情况，以及何时在包中使用它。

# 性能成本

反射允许代码灵活处理未知数据类型，通过分析它们的内存表示。这并不是没有成本的，除了复杂性之外，反射影响的另一个方面是性能。

我们可以创建一些示例来演示使用反射执行一些琐碎操作时的速度要慢得多。我们可以创建一个超时，并在 goroutines 中不断重复这些操作。当超时到期时，两个例程都将终止，我们将比较结果：

```go
func baseTest(fn1, fn2 func(int)) {
    ctx, canc := context.WithTimeout(context.Background(), time.Second)
    defer canc()
    go func() {
        for i := 0; ; i++ {
            select {
            case <-ctx.Done():
                return
            default:
                fn1(i)
            }
        }
    }()
    go func() {
        for i := 0; ; i++ {
            select {
            case <-ctx.Done():
                return
            default:
                fn2(i)
            }
        }
    }()
    <-ctx.Done()
}
```

我们可以比较普通的 map 写入与使用反射进行相同操作的速度：

```go
func testMap() {
    m1, m2 := make(map[int]int), make(map[int]int)
    m := reflect.ValueOf(m2)
    baseTest(func(i int) { m1[i] = i }, func(i int) {
        v := reflect.ValueOf(i)
        m.SetMapIndex(v, v)
    })
    fmt.Printf("normal %d\n", len(m1))
    fmt.Printf("reflect %d\n", len(m2))
}
```

我们还可以测试一下使用反射和不使用反射时读取的速度以及结构字段的设置：

```go
func testStruct() {
    type T struct {
        Field int
    }
    var m1, m2 T
    m := reflect.ValueOf(&m2).Elem()
    baseTest(func(i int) { m1.Field++ }, func(i int) {
        f := m.Field(0)
        f.SetInt(int64(f.Interface().(int) + 1))
    })
    fmt.Printf("normal %d\n", m1.Field)
    fmt.Printf("reflect %d\n", m2.Field)
}
```

通过反射执行操作时，性能至少下降了 50％，与标准的静态操作方式相比。当性能在应用程序中非常重要时，这种下降可能非常关键，但如果不是这种情况，那么使用反射可能是一个合理的选择。

# 标准库中的使用

标准库中有许多不同的包使用了`reflect`包：

+   `archive/tar`

+   `context`

+   `database/sql`

+   `encoding/asn1`

+   `encoding/binary`

+   `encoding/gob`

+   `encoding/json`

+   `encoding/xml`

+   `fmt`

+   `html/template`

+   `net/http`

+   `net/rpc`

+   `sort/slice`

+   `text/template`

我们可以思考他们对反射的处理方式，以编码包为例。这些包中的每一个都提供了编码和解码的接口，例如`encoding/json`包。我们定义了以下接口：

```go
type Marshaler interface {
    MarshalJSON() ([]byte, error)
}

type Unmarshaler interface {
    UnmarshalJSON([]byte) error
}
```

该包首先查看未知类型是否在解码或编码时实现了接口，如果没有，则使用反射。我们可以将反射视为包使用的最后资源。即使`sort`包也有一个通用的`slice`方法，使用反射来设置值和一个排序接口，避免使用反射。

还有其他包，比如`text/template`和`html/template`，它们读取运行时文本文件，其中包含关于要访问或使用的方法或字段的指令。在这种情况下，除了反射之外，没有其他方法可以完成它，也没有可以避免它的接口。

# 在包中使用反射

在了解了反射的工作原理以及它给代码增加的复杂性之后，我们可以考虑在我们正在编写的包中使用它。来自其创作者 Rob Pike 的 Go 格言之一拯救了我们：

清晰比聪明更好。反射从来不清晰。

反射的威力是巨大的，但这也是以使代码更加复杂和隐式为代价的。只有在极端必要的情况下才应该使用它，就像在模板场景中一样，并且应该在任何其他情况下避免使用它，或者至少提供一个接口来避免使用它，就像在编码包中一样。

# 属性文件

我们可以尝试使用反射来创建一个读取属性文件的包。

我们可以使用反射来创建一个读取属性文件的包：

1.  我们应该做的第一件事是定义一个避免使用反射的接口：

```go
type Unmarshaller interface {
    UnmarshalProp([]byte) error
}
```

1.  然后，我们可以定义一个解码器结构，它将利用一个`io.Reader`实例，使用行扫描器来读取各个属性：

```go
type Decoder struct {
    scanner *bufio.Scanner
}

func NewDecoder(r io.Reader) *Decoder {
    return &Decoder{scanner: bufio.NewScanner(r)}
}
```

1.  解码器也将被`Unmarshal`方法使用：

```go
func Unmarshal(data []byte, v interface{}) error {
    return NewDecoder(bytes.NewReader(data)).Decode(v)
}
```

1.  我们可以通过构建字段名称和索引的缓存来减少我们将使用反射的次数。这将很有帮助，因为在反射中，字段的值只能通过索引访问，而不能通过名称访问。

```go
var cache = make(map[reflect.Type]map[string]int)

func findIndex(t reflect.Type, k string) (int, bool) {
    if v, ok := cache[t]; ok {
        n, ok := v[k]
        return n, ok
    }
    m := make(map[string]int)
    for i := 0; i < t.NumField(); i++ {
        f := t.Field(i)
        if s := f.Name[:1]; strings.ToLower(s) == s {
            continue
        }
        name := strings.ToLower(f.Name)
        if tag := f.Tag.Get("prop"); tag != "" {
            name = tag
        }
        m[name] = i
    }
    cache[t] = m
    return findIndex(t, k)
}
```

1.  下一步是定义`Decode`方法。这将接收一个指向结构的指针，然后继续从扫描器中处理行并填充结构字段：

```go
func (d *Decoder) Decode(v interface{}) error {
    val := reflect.ValueOf(v)
    t := val.Type()
    if t.Kind() != reflect.Ptr && t.Elem().Kind() != reflect.Struct {
        return fmt.Errorf("%v not a struct pointer", t)
    }
    val = val.Elem()
    t = t.Elem()
    line := 0
    for d.scanner.Scan() {
        line++
        b := d.scanner.Bytes()
        if len(b) == 0 || b[0] == '#' {
            continue
        }
        parts := bytes.SplitN(b, []byte{':'}, 2)
        if len(parts) != 2 {
            return decodeError{line: line, err: errNoSep}
        }
        index, ok := findIndex(t, string(parts[0]))
        if !ok {
            continue
        }
        value := bytes.TrimSpace(parts[1])
        if err := d.decodeValue(val.Field(index), value); err != nil {
            return decodeError{line: line, err: err}
        }
    }
    return d.scanner.Err()
}
```

最重要的工作将由私有的`decodeValue`方法完成。首先要验证`Unmarshaller`接口是否满足，如果满足，则使用它。否则，该方法将使用反射来正确解码接收到的值。对于每种类型，它将使用`reflection.Value`的不同`Set`方法，并且如果遇到未知类型，则会返回错误：

```go
func (d *Decoder) decodeValue(v reflect.Value, value []byte) error {
    if v, ok := v.Addr().Interface().(Unmarshaller); ok {
        return v.UnmarshalProp(value)
    }
    switch valStr := string(value); v.Type().Kind() {
    case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
        i, err := strconv.ParseInt(valStr, 10, 64)
        if err != nil {
            return err
        }
        v.SetInt(i)
    case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
        i, err := strconv.ParseUint(valStr, 10, 64)
        if err != nil {
            return err
        }
        v.SetUint(i)
    case reflect.Float32, reflect.Float64:
        i, err := strconv.ParseFloat(valStr, 64)
        if err != nil {
            return err
        }
        v.SetFloat(i)
    case reflect.String:
        v.SetString(valStr)
    case reflect.Bool:
        switch value := valStr; value {
        case "true":
            v.SetBool(true)
        case "false":
            v.SetBool(false)
        default:
            return fmt.Errorf("invalid bool: %s", value)
        }
    default:
        return fmt.Errorf("invalid type: %s", v.Type())
    }
    return nil
}
```

# 使用包

为了测试包是否按预期运行，我们可以创建一个满足`Unmarshaller`接口的自定义类型。实现的类型在解码时将字符串转换为大写：

```go
type UpperString string

func (u *UpperString) UnmarshalProp(b []byte) error {
        *u = UpperString(strings.ToUpper(string(b)))
        return nil
}
```

现在我们可以将类型用作结构字段，并验证它在`decode`操作中是否被正确转换：

```go
func main() {
        r := strings.NewReader(
                "\n# comment, ignore\nkey1: 10.5\nkey2: some string" +
                        "\nkey3: 42\nkey4: false\nspecial: another string\n")
        var v struct {
                Key1 float32
                Key2 string
                Key3 uint64
                Key4 bool
                Key5 UpperString `prop:"special"`
                key6 int
        }
        if err := prop.NewDecoder(r).Decode(&v); err != nil {
                log.Fatal(r)
        }
        log.Printf("%+v", v)
}
```

# 总结

在本章中，我们详细回顾了 Go 语言接口的内存模型，强调了接口始终包含一个具体类型。我们利用这些信息更好地了解了类型转换，并理解了当一个接口被转换为另一个接口时会发生什么。

然后，我们介绍了反射的基本机制，从类型和值开始，这是该包的两种主要类型。它们分别表示变量的类型和值。值允许您读取变量的内容，如果变量是可寻址的，还可以写入它。为了使变量可寻址，需要从其地址访问变量，例如使用指针。

我们还看到了如何使用反射处理复杂的数据类型，了解如何访问结构字段值。结构的数据类型可以用于获取关于字段的元数据，包括名称和标签，这些在编码包和其他第三方库中被广泛使用。

我们看到了如何创建和操作映射，包括添加、设置和删除值。对于切片，我们看到了如何编辑它们的值以及如何执行追加操作。我们还展示了如何使用通道发送和接收数据，甚至如何像静态类型编程一样使用`select`语句。

最后，我们列出了标准库中使用反射的地方，并对其计算成本进行了快速分析。我们用一些关于何时何地使用反射的提示来结束本章，无论是在库中还是在您编写的任何应用程序中。

下一章是本书的最后一章，它解释了如何使用 CGO 在 Go 语言中利用现有的 C 库。

# 问题

1.  Go 语言中接口的内存表示是什么？

1.  当一个接口类型被转换为另一个接口类型时会发生什么？

1.  反射中的`Value`、`Type`和`Kind`是什么？

1.  如果一个值是可寻址的，这意味着什么？

1.  为什么 Go 语言中结构字段标签很重要？

1.  反射的一般权衡是什么？

1.  你能描述一种使用反射的良好方法吗？
