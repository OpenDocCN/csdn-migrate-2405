# Go 系统编程实用指南（五）

> 原文：[`zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA`](https://zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 sync 和 atomic 进行同步

本章将继续介绍 Go 并发，介绍`sync`和`atomic`包，这是另外两个用于协调 goroutine 同步的工具。这将使编写优雅且简单的代码成为可能，允许并发使用资源并管理 goroutine 的生命周期。`sync`包含高级同步原语，而`atomic`包含低级原语。

本章将涵盖以下主题：

+   锁

+   等待组

+   其他同步组件

+   `atomic`包

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅第三章，*Go 概述*。

# 同步原语

我们已经看到通道专注于 goroutine 之间的通信，现在我们将关注`sync`包提供的工具，其中包括用于 goroutine 之间同步的基本原语。我们将首先看到如何使用锁实现对同一资源的并发访问。

# 并发访问和锁

Go 提供了一个通用接口，用于可以被锁定和解锁的对象。锁定对象意味着控制它，而解锁则释放它供其他人使用。该接口为每个操作公开了一个方法。以下是代码中的示例：

```go
type Locker interface {
    Lock()
    Unlock()
}
```

# 互斥锁

锁的最简单实现是`sync.Mutex`。由于其方法具有指针接收器，因此不应通过值复制或传递。`Lock()`方法尝试控制互斥锁，如果可能的话，或者阻塞 goroutine 直到互斥锁可用。`Unlock()`方法释放互斥锁，如果在未锁定的情况下调用，则返回运行时错误。

以下是一个简单的示例，我们在其中使用锁启动一堆 goroutine，以查看哪个先执行：

```go
func main() {
    var m sync.Mutex
    done := make(chan struct{}, 10)
    for i := 0; i < cap(done); i++ {
        go func(i int, l sync.Locker) {
            l.Lock()
            defer l.Unlock()
            fmt.Println(i)
            time.Sleep(time.Millisecond * 10)
            done <- struct{}{}
        }(i, &m)
    }
    for i := 0; i < cap(done); i++ {
        <-done
    }
}
```

完整示例可在以下链接找到：[`play.golang.org/p/resVh7LImLf`](https://play.golang.org/p/resVh7LImLf)

我们使用通道来在作业完成时向主 goroutine 发出信号，并退出应用程序。让我们创建一个外部计数器，并使用 goroutine 并发地增加它。

在不同 goroutine 上执行的操作不是线程安全的，如下例所示：

```go
done := make(chan struct{}, 10000)
var a = 0
for i := 0; i < cap(done); i++ {
    go func(i int) {
        if i%2 == 0 {
            a++
        } else {
            a--
        }
        done <- struct{}{}
    }(i)
}
for i := 0; i < cap(done); i++ {
    <-done
}
fmt.Println(a)
```

我们期望得到 5000 加一和 5000 减一，最后一条指令打印出 0。然而，每次运行应用程序时，我们得到的值都不同。这是因为这种操作不是线程安全的，因此两个或更多的操作可能同时发生，最后一个操作会覆盖其他操作。这种现象被称为**竞争条件**；也就是说，多个操作试图写入相同的结果。

这意味着没有任何同步，结果是不可预测的；如果我们检查前面的示例并使用锁来避免竞争条件，我们将得到整数的值为零，这是我们期望的结果：

```go
m := sync.Mutex{}
for i := 0; i < cap(done); i++ {
    go func(l sync.Locker, i int) {
        l.Lock()
        defer l.Unlock()
        if i%2 == 0 {
            a++
        } else {
            a--
        }
        done <- struct{}{}
    }(&m, i)
    fmt.Println(a)
}
```

一个非常常见的做法是在数据结构中嵌入一个互斥锁，以表示要锁定的容器。之前的计数器变量可以表示如下：

```go
type counter struct {
    m     sync.Mutex
    value int
}
```

计数器执行的操作可以是已经在主要操作之前进行了锁定并在之后进行了解锁的方法，如下面的代码块所示：

```go
func (c *counter) Incr(){
    c.m.Lock()
    c.value++
    c.m.Unlock()
}

func (c *counter) Decr(){
    c.m.Lock()
    c.value--
    c.m.Unlock()
}

func (c *counter) Value() int {
    c.m.Lock()
    a := c.value
    c.m.Unlock()
    return a
}
```

这将简化 goroutine 循环，使代码更清晰：

```go
var a = counter{}
for i := 0; i < cap(done); i++ {
    go func(i int) {
        if i%2 == 0 {
            a.Incr()
        } else {
            a.Decr()
        }
        done <- struct{}{}
    }(i)
}
// ...
fmt.Println(a.Value())
```

# RWMutex

竞争条件的问题是由并发写入引起的，而不是由读取操作引起的。实现 locker 接口的另一个数据结构`sync.RWMutex`，旨在支持这两种操作，具有独特的写锁和与读锁互斥。这意味着互斥锁可以被单个写锁或一个或多个读锁锁定。当读者锁定互斥锁时，其他试图锁定它的读者不会被阻塞。它们通常被称为共享-独占锁。这允许读操作同时发生，而不会有等待时间。

使用 locker 接口的`Lock`和`Unlock`方法执行写锁操作。使用另外两种方法执行读取操作：`RLock`和`RUnlock`。还有另一种方法`RLocker`，它返回一个用于读取操作的 locker。

我们可以通过创建一个字符串的并发列表来快速演示它们的用法：

```go
type list struct {
    m sync.RWMutex
    value []string
}
```

我们可以迭代切片以查找所选值，并在读取时使用读锁来延迟写入：

```go
func (l *list) contains(v string) bool {
    for _, s := range l.value {
        if s == v {
            return true
        }
    }
    return false
}

func (l *list) Contains(v string) bool {
    l.m.RLock()
    found := l.contains(v)
    l.m.RUnlock()
    return found
}
```

在添加新元素时，我们可以使用写锁：

```go
func (l *list) Add(v string) bool {
    l.m.Lock()
    defer l.m.Unlock()
    if l.contains(v) {
        return false
    }
    l.value = append(l.value, v)
    return true
}
```

然后我们可以尝试使用多个 goroutines 在列表上执行相同的操作：

```go
var src = []string{
    "Ryu", "Ken", "E. Honda", "Guile",
    "Chun-Li", "Blanka", "Zangief", "Dhalsim",
}
var l list
for i := 0; i < 10; i++ {
    go func(i int) {
        for _, s := range src {
            go func(s string) {
                if !l.Contains(s) {
                    if l.Add(s) {
                        fmt.Println(i, "add", s)
                    } else {
                        fmt.Println(i, "too slow", s)
                    }
                }
            }(s)
        }
    }(i)
}
time.Sleep(500 * time.Millisecond)
```

首先我们检查名称是否包含在锁中，然后尝试添加元素。这会导致多个例程尝试添加新元素，但由于写锁是排他的，只有一个会成功。

# 写入饥饿

在设计应用程序时，这种类型的互斥锁并不总是显而易见的选择，因为在读锁的数量更多而写锁的数量较少的情况下，互斥锁将在第一个读锁之后接受更多的读锁，让写入操作等待没有活动的读锁的时刻。这是一种被称为**写入饥饿**的现象。

为了验证这一点，我们可以定义一个类型，其中包含写入和读取操作，这需要一些时间，如下面的代码所示：

```go
type counter struct {
    m sync.RWMutex
    value int
}

func (c *counter) Write(i int) {
    c.m.Lock()
    time.Sleep(time.Millisecond * 100)
    c.value = i
    c.m.Unlock()
}

func (c *counter) Value() int {
    c.m.RLock()
    time.Sleep(time.Millisecond * 100)
    a := c.value
    c.m.RUnlock()
    return a
}
```

我们可以尝试在单独的 goroutines 中以相同的节奏执行写入和读取操作，使用低于方法执行时间的持续时间（50 毫秒与 100 毫秒）。我们还将检查它们在锁定状态下花费了多少时间：

```go
var c counter
t1 := time.NewTicker(time.Millisecond * 50)
time.AfterFunc(time.Second*2, t1.Stop)
for {
    select {
    case <-t1.C:
        go func() {
            t := time.Now()
            c.Value()
            fmt.Println("val", time.Since(t))
        }()
        go func() {
            t := time.Now()
            c.Write(0)
            fmt.Println("inc", time.Since(t))
        }()
    case <-time.After(time.Millisecond * 200):
        return
    }
}
```

如果我们执行应用程序，我们会发现对于每个写入操作，都会执行多次读取，并且每次调用都会花费比上一次更多的时间，等待锁。这对于读取操作并不成立，因为它可以同时进行，所以一旦读者成功锁定资源，所有其他等待的读者也会这样做。将`RWMutex`替换为`Mutex`将使两种操作具有相同的优先级，就像前面的例子一样。

# 锁定陷阱

在锁定和解锁互斥锁时必须小心，以避免应用程序中的意外行为和死锁。参考以下代码片段：

```go
for condition {
    mu.Lock()
    defer mu.Unlock()
    action()
}
```

这段代码乍一看似乎没问题，但它将不可避免地阻塞 goroutine。这是因为`defer`语句不是在每次循环迭代结束时执行，而是在函数返回时执行。因此，第一次尝试将锁定而不释放，第二次尝试将保持锁定状态。

稍微重构一下可以帮助解决这个问题，如下面的代码片段所示：

```go
for condition {
    func() {
        mu.Lock()
        defer mu.Unlock()
        action()
    }()
}
```

我们可以使用闭包来确保即使`action`发生恐慌，也会执行延迟的`Unlock`。

如果在互斥锁上执行的操作不会引起恐慌，可以考虑放弃延迟，只在执行操作后使用它，如下所示：

```go
for condition {
    mu.Lock()
    action()
    mu.Unlock()
}
```

`defer`是有成本的，因此最好在不必要时避免使用它，例如在进行简单的变量读取或赋值时。

# 同步 goroutines

到目前为止，为了等待 goroutines 完成，我们使用了一个空结构的通道，并通过通道发送一个值作为最后一个操作，如下所示：

```go
ch := make(chan struct{})
for i := 0; i < n; n++ {
    go func() {
        // do something
        ch <- struct{}{}
    }()
}
for i := 0; i < n; n++ {
    <-ch
}
```

这种策略有效，但不是实现任务的首选方式。从语义上讲不正确，因为我们使用通道，而通道是用于通信的工具，用于发送空数据。这种用例是关于同步而不是通信。这就是为什么有`sync.WaitGroup`数据结构，它涵盖了这种情况。它有一个主要状态，称为计数器，表示等待的元素数量：

```go
type WaitGroup struct {
    noCopy noCopy
    state1 [3]uint32
}
```

`noCopy`字段防止结构通过`panic`按值复制。状态是由三个`int32`组成的数组，但只使用第一个和最后一个条目；剩下的一个用于编译器优化。

`WaitGroup`提供了三种方法来实现相同的结果：

+   `Add`：使用给定值更改计数器的值，该值也可以是负数。如果计数器小于零，应用程序将会 panic。

+   `Done`：这是`Add`的简写，参数为`-1`。通常在 goroutine 完成其工作时调用，将计数器减 1。

+   `Wait`：此操作会阻塞当前 goroutine，直到计数器达到零。

使用等待组可以使代码更清晰和可读，如下例所示：

```go
func main() {
    wg := sync.WaitGroup{}
    wg.Add(10)
    for i := 1; i <= 10; i++ {
        go func(a int) {
            for i := 1; i <= 10; i++ {
                fmt.Printf("%dx%d=%d\n", a, i, a*i)
            }
            wg.Done()
        }(i)
    }
    wg.Wait()
}
```

对于等待组，我们正在添加一个等于 goroutines 的`delta`，我们将在之前启动。在每个单独的 goroutine 中，我们使用`Done`方法来减少计数。如果 goroutines 的数量未知，则可以在启动每个 goroutine 之前执行`Add`操作（参数为`1`），如下所示：

```go
func main() {
    wg := sync.WaitGroup{}
    for i := 1; rand.Intn(10) != 0; i++ {
        wg.Add(1)
        go func(a int) {
            for i := 1; i <= 10; i++ {
                fmt.Printf("%dx%d=%d\n", a, i, a*i)
            }
            wg.Done()
        }(i)
    }
    wg.Wait()
}
```

在前面的示例中，我们每次`for`循环迭代有 10%的机会完成，因此在启动 goroutine 之前我们会向组中添加一个。

一个非常常见的错误是在 goroutine 内部添加值，这通常会导致在没有执行任何 goroutine 的情况下过早退出。这是因为应用程序在创建 goroutines 并执行`Wait`函数之前开始并添加它们自己的增量，如下例所示：

```go
func main() {
    wg := sync.WaitGroup{}
    for i := 1; i < 10; i++ {
        go func(a int) {
            wg.Add(1)
            for i := 1; i <= 10; i++ {
                fmt.Printf("%dx%d=%d\n", a, i, a*i)
            }
            wg.Done()
        }(i)
    }
    wg.Wait()
}
```

此应用程序不会打印任何内容，因为它在任何 goroutine 启动和调用`Add`方法之前到达`Wait`语句。

# Go 中的单例

单例模式是软件开发中常用的策略。这涉及将某种类型的实例数量限制为一个，并在整个应用程序中使用相同的实例。该概念的一个非常简单的实现可能是以下代码：

```go
type obj struct {}

var instance *obj

func Get() *obj{
    if instance == nil {
        instance = &obj{}
    }
    return instance
}
```

这在连续的情况下是完全可以的，但在并发的情况下，就像许多 Go 应用程序一样，这是不安全的，并且可能会产生竞争条件。

通过添加一个锁，可以使前面的示例线程安全，从而避免任何竞争条件，如下所示：

```go
type obj struct {}

var (
    instance *obj
    lock     sync.Mutex
)

func Get() *obj{
    lock.Lock()
    defer lock.Unlock()
    if instance == nil {
        instance = &obj{}
    }
    return instance
}
```

这是安全的，但速度较慢，因为`Mutex`将在每次请求实例时进行同步。

实现此模式的最佳解决方案是使用`sync.Once`结构，如下例所示，它负责使用`Mutex`和`atomic`读取一次执行函数（我们将在本章的第二部分中看到）：

```go
type obj struct {}

var (
    instance *obj
    once     sync.Once
)

func Get() *obj{
    once.Do(func(){
        instance = &obj{}
    })
    return instance
}
```

结果代码是惯用的和清晰的，与互斥解决方案相比性能更好。由于操作只会执行一次，我们还可以摆脱在先前示例中对实例进行的`nil`检查。

# 一次和重置

`sync.Once`函数用于执行另一个函数一次，不再执行。有一个非常有用的第三方库，允许我们使用`Reset`方法重置单例的状态。

包的源代码可以在以下位置找到：[github.com/matryer/resync](https://github.com/matryer/resync)。

典型用途包括一些需要在特定错误上再次执行的初始化，例如获取 API 密钥或在连接中断时重新拨号。

# 资源回收

我们已经看到如何在上一章中使用具有工作池的缓冲通道来实现资源回收。将有两种方法如下：

+   一个`Get`方法，尝试从通道接收消息或返回一个新实例。

+   一个`Put`方法，尝试将实例返回到通道或丢弃它。

这是一个使用通道实现的简单池的实现：

```go
type A struct{}

type Pool chan *A

func (p Pool) Get() *A {
    select {
    case a := <-p:
        return a
    default:
        return new(A)
    }
}

func (p Pool) Put(a *A) {
    select {
    case p <- a:
    default:
    }
}
```

我们可以使用`sync.Pool`结构来改进这一点，它实现了一个线程安全的对象集，可以保存或检索。唯一需要定义的是当创建一个新对象时池的行为：

```go
type Pool struct {
    // New optionally specifies a function to generate
    // a value when Get would otherwise return nil.
    // It may not be changed concurrently with calls to Get.
    New func() interface{}
    // contains filtered or unexported fields
}
```

池提供两种方法：`Get`和`Put`。这些方法从池中返回对象（或创建新对象），并将对象放回池中。由于`Get`方法返回一个`interface{}`，因此需要将值转换为特定类型才能正确使用。我们已经广泛讨论了缓冲区回收，在以下示例中，我们将尝试使用`sync.Pool`来实现缓冲区回收。

我们需要定义池和函数来获取和释放新的缓冲区。我们的缓冲区将具有 4 KB 的初始容量，并且`Put`函数将确保在将其放回池之前重置缓冲区，如以下代码示例所示：

```go
var pool = sync.Pool{
    New: func() interface{} {
        return bytes.NewBuffer(make([]byte, 0, 4096))
    },
}

func Get() *bytes.Buffer {
    return pool.Get().(*bytes.Buffer)
}

func Put(b *bytes.Buffer) {
    b.Reset()
    pool.Put(b)
}
```

现在我们将创建一系列 goroutine，它们将使用`WaitGroup`来在完成时发出信号，并将执行以下操作：

+   等待一定时间（1-5 秒）。

+   获取一个缓冲区。

+   在缓冲区上写入信息。

+   将内容复制到标准输出。

+   释放缓冲区。

我们将使用等于`1`秒的睡眠时间，每`4`次循环增加一秒，最多达到`5`秒：

```go
start := time.Now()
wg := sync.WaitGroup{}
wg.Add(20)
for i := 0; i < 20; i++ {
    go func(v int) {
        time.Sleep(time.Second * time.Duration(1+v/4))
        b := Get()
        defer func() {
            Put(b)
            wg.Done()
        }()
        fmt.Fprintf(b, "Goroutine %2d using %p, after %.0fs\n", v, b, time.Since(start).Seconds())
        fmt.Printf("%s", b.Bytes())
    }(i)
}
wg.Wait()
```

打印的信息还包含缓冲区内存地址。这将帮助我们确认缓冲区始终相同，没有创建新的缓冲区。

# 切片回收问题

对于具有基础字节片的数据结构，例如`bytes.Buffer`，在与`sync.Pool`或类似的回收机制结合使用时，我们应该小心。让我们改变先前的示例，收集缓冲区的字节而不是将它们打印到标准输出。以下是此示例的示例代码：

```go
var (
    list = make([][]byte, 20)
    m sync.Mutex
)
for i := 0; i < 20; i++ {
    go func(v int) {
        time.Sleep(time.Second * time.Duration(1+v/4))
        b := Get()
        defer func() {
            Put(b)
            wg.Done()
        }()
        fmt.Fprintf(b, "Goroutine %2d using %p, after %.0fs\n", v, b, time.Since(start).Seconds())
        m.Lock()
        list[v] = b.Bytes()
        m.Unlock()
    }(i)
}
wg.Wait()
```

那么，当我们打印字节片段列表时会发生什么？我们可以在以下示例中看到这一点：

```go

for i := range list {
    fmt.Printf("%d - %s", i, list[i])
}
```

由于缓冲区正在重用相同的基础切片，并且在每次新使用时覆盖内容，因此我们得到了意外的结果。

通常解决此问题的方法是执行字节的副本，而不仅仅是分配它们：

```go
m.Lock()
list[v] = make([]byte, b.Len())
copy(list[v], b.Bytes())
m.Unlock()
```

# 条件

在并发编程中，条件变量是一个同步机制，其中包含等待相同条件进行验证的线程。在 Go 中，这意味着有一些 goroutine 在等待某些事情发生。我们已经使用单个 goroutine 等待通道的实现，如以下示例所示：

```go
ch := make(chan struct{})
go func() {
    // do something
    ch <- struct{}{}
}()
go func() {
    // wait for condition
    <-ch
    // do something else
}
```

这种方法仅限于单个 goroutine，但可以改进为支持更多侦听器，从发送消息切换到关闭通道：

```go
go func() {
    // do something
    close(ch)
}()
for i := 0; i < n; i++ {
    go func() {
        // wait for condition
        <-ch
        // do something else
    }()
}
```

关闭通道适用于多个侦听器，但在关闭后不允许它们进一步使用通道。

`sync.Cond`类型是一个工具，可以更好地处理所有这些行为。它在实现中使用锁，并公开三种方法：

+   `Broadcast`：这会唤醒等待条件的所有 goroutine。

+   `Signal`：如果至少有一个条件，则唤醒等待条件的单个 goroutine。

+   `Wait`：这会解锁锁定器，暂停 goroutine 的执行，稍后恢复执行并再次锁定它，等待`Broadcast`或`Signal`。

这不是必需的，但可以在持有锁时执行`Broadcast`和`Signal`操作，在调用之前锁定它，之后释放它。`Wait`方法要求在调用之前持有锁，并在使用条件后解锁。

让我们创建一个并发应用程序，该应用程序使用`sync.Cond`来协调更多的 goroutines。我们将从命令行获得提示，每条记录将被写入一系列文件。我们将有一个主结构来保存所有数据：

```go
type record struct {
    sync.Mutex
    buf string
    cond *sync.Cond
    writers []io.Writer
}
```

我们将监视的条件是`buf`字段的更改。在`Run`方法中，`record`结构将启动多个 goroutines，每个写入者一个。每个 goroutine 将等待条件触发，并将写入其文件：

```go
func (r *record) Run() {
    for i := range r.writers {
        go func(i int) {
            for {
                r.Lock()
                r.cond.Wait()
                fmt.Fprintf(r.writers[i], "%s\n", r.buf)
                r.Unlock()
            }
        }(i)
    }
}
```

我们可以看到，在使用`Wait`之前锁定条件，并在使用我们条件引用的值之后解锁它。主函数将根据提供的命令行参数创建一个记录和一系列文件：

```go
// let's make sure we have at least a file argument
if len(os.Args) < 2 {
    log.Fatal("Please specify at least a file")
}
r := record{
    writers: make([]io.Writer, len(os.Args)-1),
}
r.cond = sync.NewCond(&r)
for i, v := range os.Args[1:] {
    f, err := os.Create(v)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    r.writers[i] = f
}
r.Run()
```

然后我们将使用`bufio.Scanner`读取行并广播`buf`字段的更改。我们还将接受特殊值`\q`作为退出命令：

```go
scanner := bufio.NewScanner(os.Stdin)
for {
    fmt.Printf(":> ")
    if !scanner.Scan() {
        break
    }
    r.Lock()
    r.buf = scanner.Text()
    r.Unlock()
    switch {
    case r.buf == `\q`:
        return
    default:
        r.cond.Broadcast()
    }
}
```

我们可以看到，在持有锁时更改`buf`，然后调用`Broadcast`唤醒等待条件的所有 goroutines。

# 同步地图

Go 中的内置地图不是线程安全的，因此尝试从不同的 goroutines 进行写入可能会导致运行时错误：`concurrent map writes`。我们可以使用一个简单的程序来验证这一点，该程序尝试并发进行更改：

```go
func main() {
    var m = map[int]int{}
    wg := sync.WaitGroup{}
    wg.Add(10)
    for i := 0; i < 10; i++ {
        go func(i int) {
            m[i%5]++
            fmt.Println(m)
            wg.Done()
        }(i)
    }
    wg.Wait()
}
```

在写入时进行读取也会导致运行时错误，即`concurrent map iteration and map write`，我们可以通过运行以下示例来看到这一点：

```go
func main() {
    var m = map[int]int{}
    var done = make(chan struct{})
    go func() {
        for i := 0; i < 100; i++ {
            time.Sleep(time.Nanosecond)
            m[i]++
        }
        close(done)
    }()
    for {
        time.Sleep(time.Nanosecond)
        fmt.Println(len(m), m)
        select {
        case <-done:
            return
        default:
        }
    }
}
```

有时，尝试迭代地图（如`Print`语句所做的那样）可能会导致恐慌，例如`index out of range`，因为内部切片可能已经在其他地方分配了。

使地图并发的一个非常简单的策略是将其与`sync.Mutex`或`sync.RWMutex`配对。这样可以在执行操作时锁定地图：

```go
type m struct {
    sync.Mutex
    m map[int]int
}
```

我们使用地图来获取或设置值，例如以下示例：

```go
func (m *m) Get(key int) int {
    m.Lock()
    a := m.m[key]
    m.Unlock()
    return a
}

func (m *m) Put(key, value int) {
    m.Lock()
    m.m[key] = value
    m.Unlock()
}
```

我们还可以传递一个接受键值对并对每个元组执行的函数，同时锁定地图：

```go
func (m *m) Range(f func(k, v int)) {
    m.Lock()
    for k, v := range m.m {
        f(k, v)
    }
    m.Unlock()
}
```

Go 1.9 引入了一个名为`sync.Map`的结构，它正是这样做的。它是一个非常通用的`map[interface{}]interface{}`，可以使用以下方法执行线程安全操作：

+   `Load`：从地图中获取给定键的值。

+   `Store`：为给定的键在地图中设置一个值。

+   `Delete`：从地图中删除给定键的条目。

+   `LoadOrStore`：返回键的值（如果存在）或存储的值。

+   `Range`：调用一个函数，该函数针对地图中的每个键值对返回一个布尔值。如果返回`false`，则迭代停止。

我们可以在以下代码片段中看到这是如何工作的，我们尝试同时进行多次写入：

```go
func main() {
    var m = sync.Map{}
    var wg = sync.WaitGroup{}
    wg.Add(1000)
    for i := 0; i < 1000; i++ {
        go func(i int) {
            m.LoadOrStore(i, i)
            wg.Done()
        }(i)
    }
    wg.Wait()
    i := 0
    m.Range(func(k, v interface{}) bool {
        i++
        return true
    })
   fmt.Println(i)
}
```

与具有常规`Map`的版本不同，此应用程序不会崩溃并执行所有操作。

# 信号量

在上一章中，我们看到可以使用通道创建加权信号量。在实验性的`sync`包中有更好的实现。可以在[golang.org/x/sync/semaphore](https://godoc.org/golang.org/x/sync/semaphore)找到。

这种实现使得可以创建一个新的信号量，使用`semaphore.NewWeighted`指定权重。

可以使用`Acquire`方法获取配额，指定要获取的配额数量。这些可以使用`Release`方法释放，如以下示例所示：

```go
func main() {
    s := semaphore.NewWeighted(int64(10))
    ctx := context.Background()
    for i := 0; i < 20; i++ {
        if err := s.Acquire(ctx, 1); err != nil {
            log.Fatal(err)
        }
        go func(i int) {
            fmt.Println(i)
            s.Release(1)
        }(i)
    }
    time.Sleep(time.Second)
}
```

获取配额除了数字之外还需要另一个参数，即`context.Context`。这是 Go 中可用的另一个并发工具，我们将在下一章中看到如何使用它。

# 原子操作

`sync`包提供了同步原语，在底层使用整数和指针的线程安全操作。我们可以在另一个名为`sync/atomic`的包中找到这些功能，该包可用于创建特定于用户用例的工具，具有更好的性能和更少的内存使用。

# 整数操作

有一系列针对不同类型整数的指针的函数：

+   `int32`

+   `int64`

+   `uint32`

+   `uint64`

+   `uintptr`

这包括表示指针的特定类型的整数，`uintptr`。这些类型可用的操作如下：

+   `Load`：从指针中检索整数值

+   `Store`：将整数值存储在指针中

+   `Add`：将指定的增量添加到指针值

+   `Swap`：将新值存储在指针中并返回旧值

+   `CompareAndSwap`：仅当新值与指定值相同时才将其交换

# 点击器

这个函数对于非常容易定义线程安全的组件非常有帮助。一个非常明显的例子可能是一个简单的整数计数器，它使用`Add`来改变计数器，`Load`来检索当前值，`Store`来重置它：

```go
type clicker int32

func (c *clicker) Click() int32 {
    return atomic.AddInt32((*int32)(c), 1)
}

func (c *clicker) Reset() {
    atomic.StoreInt32((*int32)(c), 0)
}

func (c *clicker) Value() int32 {
    return atomic.LoadInt32((*int32)(c))
}
```

我们可以在一个简单的程序中看到它的运行情况，该程序尝试同时读取、写入和重置计数器。

我们定义`clicker`和`WaitGroup`，并将正确数量的元素添加到等待组中，如下所示：

```go
c := clicker(0)
wg := sync.WaitGroup{}
// 2*iteration + reset at 5
wg.Add(21)
```

我们可以启动一堆不同操作的 goroutines，比如：10 次读取，10 次添加和一次重置：

```go
for i := 0; i < 10; i++ {
    go func() {
        c.Click()
        fmt.Println("click")
        wg.Done()
    }()
    go func() {
        fmt.Println("load", c.Value())
        wg.Done()
    }()
    if i == 0 || i%5 != 0 {
        continue
    }
    go func() {
        c.Reset()
        fmt.Println("reset")
        wg.Done()
    }()
}
wg.Wait()
```

我们将看到点击器按照预期的方式执行并发求和而没有竞争条件。

# 线程安全的浮点数

`atomic`包仅提供整数的原语，但由于`float32`和`float64`存储在与`int32`和`int64`相同的数据结构中，我们使用它们来创建原子浮点值。

诀窍是使用`math.Floatbits`函数将浮点数表示为无符号整数，以及使用`math.Floatfrombits`函数将无符号整数转换为浮点数。让我们看看这如何在`float64`中工作：

```go
type f64 uint64

func uf(u uint64) (f float64) { return math.Float64frombits(u) }
func fu(f float64) (u uint64) { return math.Float64bits(f) }

func newF64(f float64) *f64 {
    v := f64(fu(f))
    return &v
}

func (f *f64) Load() float64 {
  return uf(atomic.LoadUint64((*uint64)(f)))
}

func (f *f64) Store(s float64) {
  atomic.StoreUint64((*uint64)(f), fu(s))
}
```

创建`Add`函数有点复杂。我们需要使用`Load`获取值，然后比较和交换。由于这个操作可能失败，因为加载是一个`atomic`操作，**比较和交换**（**CAS**）是另一个，我们在循环中不断尝试直到成功：

```go
func (f *f64) Add(s float64) float64 {
    for {
        old := f.Load()
        new := old + s
        if f.CompareAndSwap(old, new) {
            return new
        }
    }
}

func (f *f64) CompareAndSwap(old, new float64) bool {
    return atomic.CompareAndSwapUint64((*uint64)(f), fu(old), fu(new))
}
```

# 线程安全的布尔值

我们也可以使用`int32`来表示布尔值。我们可以使用整数`0`作为`false`，`1`作为`true`，创建一个线程安全的布尔条件：

```go
type cond int32

func (c *cond) Set(v bool) {
    a := int32(0)
    if v {
        a++
    }
    atomic.StoreInt32((*int32)(c), a)
}

func (c *cond) Value() bool {
    return atomic.LoadInt32((*int32)(c)) != 0
}
```

这将允许我们将`cond`类型用作线程安全的布尔值。

# 指针操作

Go 中的指针变量存储在`intptr`变量中，这些整数足够大以容纳内存地址。`atomic`包使得可以对其他整数类型执行相同的操作。有一个允许不安全指针操作的包，它提供了`unsafe.Pointer`类型，用于原子操作。

在下面的示例中，我们定义了两个整数变量及其相关的整数指针。然后我们执行第一个指针与第二个指针的交换：

```go
v1, v2 := 10, 100
p1, p2 := &v1, &v2
log.Printf("P1: %v, P2: %v", *p1, *p2)
atomic.SwapPointer((*unsafe.Pointer)(unsafe.Pointer(&p1)), unsafe.Pointer(p2))
log.Printf("P1: %v, P2: %v", *p1, *p2)
v1 = -10
log.Printf("P1: %v, P2: %v", *p1, *p2)
v2 = 3
log.Printf("P1: %v, P2: %v", *p1, *p2)
```

交换后，两个指针现在都指向第二个变量；对第一个值的任何更改都不会影响指针。更改第二个变量会改变指针所指的值。

# 值

我们可以使用的最简单的工具是`atomic.Value`。它保存`interface{}`，并且可以通过线程安全地读取和写入它。它公开了两种方法，`Store`和`Load`，这使得设置或检索值成为可能。正如其他线程安全工具一样，`sync.Value`在第一次使用后不能被复制。

我们可以尝试有许多 goroutines 来设置和读取相同的值。每次加载操作都会获取最新存储的值，并且并发时不会出现错误：

```go
func main() {
    var (
        v atomic.Value
        wg sync.WaitGroup
    )
    wg.Add(20)
    for i := 0; i < 10; i++ {
        go func(i int) {
            fmt.Println("load", v.Load())
            wg.Done()
        }(i)
        go func(i int) {
            v.Store(i)
            fmt.Println("store", i)
            wg.Done()
        }(i)
    }
    wg.Wait()
}
```

这是一个非常通用的容器；它可以用于任何类型的变量，变量类型应该从一个变为另一个。如果具体类型发生变化，它将使方法恐慌；同样的情况也适用于`nil`空接口。

# 底层

`sync.Value`类型将其数据存储在一个非公开的接口中，如源代码所示：

```go
type Value struct {
    v interface{}
}
```

它使用`unsafe`包的一种类型来将该结构转换为另一个具有与接口相同的数据结构：

```go
type ifaceWords struct {
    typ unsafe.Pointer
    data unsafe.Pointer
}
```

具有完全相同内存布局的两种类型可以以这种方式转换，跳过 Go 的类型安全性。这使得可以使用指针进行 `atomic` 操作，并执行线程安全的 `Store` 和 `Load` 操作。

为了写入值获取锁，`atomic.Value` 使用与类型中的 `unsafe.Pointer(^uintptr(0))` 值（即 `0xffffffff`）进行比较和交换操作；它改变值并用正确的值替换类型。

同样，加载操作会循环，直到类型不同于 `0xffffffff`，然后尝试读取值。

使用这种方法，`atomic.Value` 能够使用其他 `atomic` 操作存储和加载任何值。

# 总结

在本章中，我们看到了 Go 标准包中用于同步的工具。它们位于两个包中：`sync`，提供诸如互斥锁之类的高级工具，以及 `sync/atomic`，执行低级操作。

首先，我们看到了如何使用锁同步数据。我们看到了如何使用 `sync.Mutex` 来锁定资源，而不管操作类型如何，并使用 `sync.RWMutex` 允许并发读取和阻塞写入。我们应该小心使用第二个，因为连续读取可能会延迟写入。

接下来，我们看到了如何跟踪正在运行的操作，以便等待一系列 goroutine 的结束，使用 `sync.WaitGroup`。这充当当前 goroutine 的线程安全计数器，并使得可以使用 `Wait` 方法将当前 goroutine 置于休眠状态，直到计数达到零。

此外，我们检查了 `sync.Once` 结构，用于执行功能一次，例如允许实现线程安全的单例。然后我们使用 `sync.Pool` 在可能的情况下重用实例而不是创建新实例。池需要的唯一东西是返回新实例的函数。

`sync.Condition` 结构表示特定条件并使用锁来改变它，允许 goroutine 等待改变。这可以使用 `Signal` 传递给单个 goroutine，或者使用 `Broadcast` 传递给所有 goroutine。该包还提供了 `sync.Map` 的线程安全版本。

最后，我们检查了 `atomic` 的功能，这些功能主要是整数线程安全操作：加载、保存、添加、交换和 CAS。我们还看到了 `atomic.Value`，它使得可以并发更改接口的值，并且在第一次更改后不允许更改类型。

下一章将介绍 Go 并发中引入的最新元素：`Context`，这是一个处理截止日期、取消等的接口。

# 问题

1.  什么是竞争条件？

1.  当您尝试并发执行地图的读取和写入操作时会发生什么？

1.  `Mutex` 和 `RWMutex` 之间有什么区别？

1.  等待组有什么用？

1.  `Once` 的主要用途是什么？

1.  您如何使用 `Pool`？

1.  使用原子操作的优势是什么？


# 第十三章：使用上下文进行协调

本章是关于相对较新的上下文包及其在并发编程中的使用。它是一个非常强大的工具，通过定义一个在标准库中的许多不同位置以及许多第三方包中使用的独特接口。

本章将涵盖以下主题：

+   理解上下文是什么

+   在标准库中研究其用法

+   创建使用上下文的包

# 技术要求

本章需要安装 Go 并设置您喜欢的编辑器。有关更多信息，请参阅第三章，*Go 概述*。

# 理解上下文

上下文是在 1.7 版本中进入标准库的相对较新的组件。它是用于 goroutine 之间同步的接口，最初由 Go 团队内部使用，最终成为语言的核心部分。

# 接口

该包中的主要实体是`Context`本身，它是一个接口。它只有四种方法：

```go
type Context interface {
    Deadline() (deadline time.Time, ok bool)
    Done() <-chan struct{}
    Err() error
    Value(key interface{}) interface{}
}
```

让我们在这里了解这四种方法：

+   `Deadline`：返回上下文应该被取消的时间，以及一个布尔值，当没有截止日期时为`false`

+   `Done`：返回一个只接收空结构的通道，用于信号上下文应该被取消

+   `Err`：当`done`通道打开时返回`nil`；否则返回上下文取消的原因

+   `Value`：返回与当前上下文中的键关联的值，如果该键没有值，则返回`nil`

与标准库的其他接口相比，上下文具有许多方法，通常只有一两个方法。其中三个方法密切相关：

+   `Deadline`是取消的时间

+   `Done`信号上下文已完成

+   `Err`返回取消的原因

最后一个方法`Value`返回与某个键关联的值。包的其余部分是一系列函数，允许您创建不同类型的上下文。让我们浏览包含在该包中的各种函数，并查看创建和装饰上下文的各种工具。

# 默认上下文

`TODO`和`Background`函数返回`context.Context`，无需任何输入参数。返回的值是一个空上下文，它们之间的区别只是语义上的。

# Background

`Background`是一个空上下文，不会被取消，没有截止日期，也不保存任何值。它主要由`main`函数用作根上下文或用于测试目的。以下是此上下文的一些示例代码：

```go
func main() {
    ctx := context.Background()
    done := ctx.Done()
    for i :=0; ;i++{
        select {
        case <-done:
            return
        case <-time.After(time.Second):
            fmt.Println("tick", i)
        }
    }
}
```

完整示例可在此处找到：[`play.golang.org/p/y_3ip7sdPnx`](https://play.golang.org/p/y_3ip7sdPnx)。

我们可以看到，在示例的上下文中，循环无限进行，因为上下文从未完成。

# TODO

`TODO`是另一个空上下文，当上下文的范围不清楚或上下文的类型尚不可用时应使用。它的使用方式与`Background`完全相同。实际上，在底层，它们是相同的东西；区别只是语义上的。如果我们查看源代码，它们具有完全相同的定义：

```go
var (
    background = new(emptyCtx)
    todo = new(emptyCtx)
)
```

该代码的源代码可以在[`golang.org/pkg/context/?m=all#pkg-variables`](https://golang.org/pkg/context/?m=all#pkg-variables)找到。

可以使用包的其他函数来扩展这些基本上下文。它们将充当装饰器，并为它们添加更多功能。

# 取消、超时和截止日期

我们查看的上下文从未被取消，但该包提供了不同的选项来添加此功能。

# 取消

`context.WithCancel`装饰器函数获取一个上下文并返回另一个上下文和一个名为`cancel`的函数。返回的上下文将是具有不同`done`通道（标记当前上下文完成的通道）的上下文的副本，当父上下文完成或调用`cancel`函数时关闭该通道-无论哪个先发生。

在以下示例中，我们可以看到在调用`cancel`函数之前等待几秒钟，程序正确终止。`Err`的值是`context.Canceled`变量：

```go
func main() {
    ctx, cancel := context.WithCancel(context.Background())
    time.AfterFunc(time.Second*5, cancel)
    done := ctx.Done()
    for i := 0; ; i++ {
        select {
        case <-done:
            fmt.Println("exit", ctx.Err())
            return
        case <-time.After(time.Second):
            fmt.Println("tick", i)
        }
    }
}
```

完整示例在这里：[`play.golang.org/p/fNHLIZL8e0L`](https://play.golang.org/p/fNHLIZL8e0L)。

# 截止时间

`context.WithDeadline`是另一个装饰器，它将`time.Time`作为时间截止时间，并将其应用于另一个上下文。如果已经有截止时间并且早于提供的截止时间，则指定的截止时间将被忽略。如果在截止时间到达时`done`通道仍然打开，则会自动关闭它。

在以下示例中，我们将截止时间设置为现在的 5 秒后，并在 10 秒后调用`cancel`。截止时间在取消之前到达，`Err`返回`context.DeadlineExceeded`错误：

```go
func main() {
    ctx, cancel := context.WithDeadline(context.Background(), 
         time.Now().Add(5*time.Second))
    time.AfterFunc(time.Second*10, cancel)
    done := ctx.Done()
    for i := 0; ; i++ {
        select {
        case <-done:
            fmt.Println("exit", ctx.Err())
            return
        case <-time.After(time.Second):
            fmt.Println("tick", i)
        }
    }
}
```

完整示例在这里：[`play.golang.org/p/iyuOmd__CGH`](https://play.golang.org/p/iyuOmd__CGH)。

我们可以看到前面的示例的行为与预期完全一致。它将打印`tick`语句每秒几次，直到截止时间到达并返回错误。

# 超时

最后一个与取消相关的装饰器是`context.WithTimeout`，它允许您指定`time.Duration`以及上下文，并在超时时自动关闭`done`通道。

如果有截止时间活动，则新值仅在早于父级时应用。我们可以看一个几乎相同的示例，除了上下文定义之外，得到与截止时间示例相同的结果：

```go
func main() {
    ctx, cancel := context.WithTimeout(context.Background(),5*time.Second)
    time.AfterFunc(time.Second*10, cancel)
    done := ctx.Done()
    for i := 0; ; i++ {
        select {
        case <-done:
            fmt.Println("exit", ctx.Err())
            return
        case <-time.After(time.Second):
            fmt.Println("tick", i)
        }
    }
}
```

完整示例在这里：[`play.golang.org/p/-Zp63_e0zYD`](https://play.golang.org/p/-Zp63_e0zYD)。

# 键和值

`context.WithValue`函数创建了一个父上下文的副本，其中给定的键与指定的值相关联。它的范围包含相对于单个请求的值，而在处理过程中不应该用于其他范围，例如可选的函数参数。

键应该是可以比较的东西，最好避免使用`string`值，因为使用上下文的两个不同包可能会覆盖彼此的值。建议使用用户定义的具体类型，如`struct{}`。

在这里，我们可以看到一个示例，我们使用空结构作为键，为每个 goroutine 添加不同的值：

```go
type key struct{}

type key struct{}

func main() {
    ctx, canc := context.WithCancel(context.Background())
    wg := sync.WaitGroup{}
    wg.Add(5)
    for i := 0; i < 5; i++ {
        go func(ctx context.Context) {
            v := ctx.Value(key{})
            fmt.Println("key", v)
            wg.Done()
            <-ctx.Done()
            fmt.Println(ctx.Err(), v)
        }(context.WithValue(ctx, key{}, i))
    }
    wg.Wait()
    canc()
    time.Sleep(time.Second)
}

```

完整示例在这里：[`play.golang.org/p/lM61u_QKEW1`](https://play.golang.org/p/lM61u_QKEW1)。

我们还可以看到取消父级会取消其他上下文。另一个有效的键类型可以是导出的指针值，即使底层数据相同也不会相同：

```go
type key *int

func main() {
    k := new(key)
    ctx, canc := context.WithCancel(context.Background())
    wg := sync.WaitGroup{}
    wg.Add(5)
    for i := 0; i < 5; i++ {
        go func(ctx context.Context) {
            v := ctx.Value(k)
            fmt.Println("key", v, ctx.Value(new(key)))
            wg.Done()
            <-ctx.Done()
            fmt.Println(ctx.Err(), v)
        }(context.WithValue(ctx, k, i))
    }
    wg.Wait()
    canc()
    time.Sleep(time.Second)
}
```

完整示例在这里：[`play.golang.org/p/05XJwWF0-0n`](https://play.golang.org/p/05XJwWF0-0n)。

我们可以看到，定义具有相同底层值的键指针不会返回预期的值。

# 标准库中的上下文

现在我们已经介绍了包的内容，我们将看看如何在标准包或应用程序中使用它们。上下文在标准包中的一些函数和方法中使用，主要是网络包。现在让我们来看看它们：

+   `http.Server`使用`Shutdown`方法，以便完全控制超时或取消操作。

+   `http.Request`允许您使用`WithContext`方法设置上下文。它还允许您使用`Context`获取当前上下文。

+   在`net`包中，`Listen`，`Dial`和`Lookup`有一个使用`Context`来控制截止时间和超时的版本。

+   在`database/sql`包中，上下文用于停止或超时许多不同的操作。

# HTTP 请求

在官方包引入之前，每个与 HTTP 相关的框架都使用自己的版本上下文来存储与 HTTP 请求相关的数据。这导致了碎片化，并且在不重写中间件或任何特定绑定代码的情况下无法重用处理程序和中间件。

# 传递作用域值

在`http.Request`中引入`context.Context`试图通过定义一个可以分配、恢复和在各种处理程序中使用的单一接口来解决这个问题。

缺点是上下文不会自动分配给请求，并且上下文值不能被回收利用。没有真正好的理由这样做，因为上下文应该存储特定于某个包或范围的数据，而包本身应该是唯一能够与它们交互的对象。

一个很好的模式是使用一个独特的未导出的密钥类型，结合辅助函数来获取或设置特定的值：

```go
type keyType struct{}

var key = &keyType{}

func WithKey(ctx context.Context, value string) context.Context {
    return context.WithValue(ctx, key, value)
}

func GetKey(ctx context.Context) (string, bool) {
    v := ctx.Value(key)
    if v == nil {
        return "", false
    }
    return v.(string), true
}
```

上下文请求是标准库中唯一存储在数据结构中的情况，使用`WithContext`方法存储，并使用`Context`方法访问。这样做是为了不破坏现有代码，并保持 Go 1 的兼容性承诺。

完整示例在此处可用：[`play.golang.org/p/W6gGp_InoMp`](https://play.golang.org/p/W6gGp_InoMp)。

# 请求取消

上下文的一个很好的用法是在使用`http.Client`执行 HTTP 请求时进行取消和超时处理，它会自动处理上下文中的中断。以下示例正是如此：

```go
func main() {
    const addr = "localhost:8080"
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(time.Second * 5)
    })
    go func() {
        if err := http.ListenAndServe(addr, nil); err != nil {
            log.Fatalln(err)
        }
    }()
    req, _ := http.NewRequest(http.MethodGet, "http://"+addr, nil)
    ctx, canc := context.WithTimeout(context.Background(), time.Second*2)
    defer canc()
    time.Sleep(time.Second)
    if _, err := http.DefaultClient.Do(req.WithContext(ctx)); err != nil {
        log.Fatalln(err)
    }
}
```

上下文取消方法也可以用于中断传递给客户端的当前 HTTP 请求。在调用不同的端点并返回收到的第一个结果的情况下，取消其他请求是一个好主意。

让我们创建一个应用程序，它在不同的搜索引擎上运行查询，并返回最快的结果，取消其他搜索。我们可以创建一个 Web 服务器，它有一个唯一的端点，在 0 到 10 秒内回复：

```go
const addr = "localhost:8080"
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    d := time.Second * time.Duration(rand.Intn(10))
    log.Println("wait", d)
    time.Sleep(d)
})
go func() {
    if err := http.ListenAndServe(addr, nil); err != nil {
        log.Fatalln(err)
    }
}()
```

我们可以为请求使用可取消的上下文，结合等待组将其与请求结束同步。每个 goroutine 将创建一个请求，并尝试使用通道发送结果。由于我们只对第一个感兴趣，我们将使用`sync.Once`来限制它：

```go
ctx, canc := context.WithCancel(context.Background())
ch, o, wg := make(chan int), sync.Once{}, sync.WaitGroup{}
wg.Add(10)
for i := 0; i < 10; i++ {
    go func(i int) {
        defer wg.Done()
        req, _ := http.NewRequest(http.MethodGet, "http://"+addr, nil)
        if _, err := http.DefaultClient.Do(req.WithContext(ctx)); err != nil {
            log.Println(i, err)
            return
        }
        o.Do(func() { ch <- i })
    }(i)
}
log.Println("received", <-ch)
canc()
log.Println("cancelling")
wg.Wait()
```

当此程序运行时，我们将看到其中一个请求成功完成并发送到通道，而其他请求要么被取消，要么被忽略。

# HTTP 服务器

`net/http`包中有几种上下文的用法，包括停止监听器或成为请求的一部分。

# 关闭

`http.Server`允许我们为关闭操作传递上下文。这使我们能够使用一些上下文的功能，如取消和超时。我们可以定义一个新的服务器及其`mux`和可取消的上下文：

```go
mux := http.NewServeMux()
server := http.Server{
    Addr: ":3000",
    Handler: mux,
}
ctx, canc := context.WithCancel(context.Background())
defer canc()
mux.HandleFunc("/shutdown", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("OK"))
    canc()
})
```

我们可以在一个单独的 goroutine 中启动服务器：

```go
go func() {
    if err := server.ListenAndServe(); err != nil {
        if err != http.ErrServerClosed {
            log.Fatal(err)
        }
    }
}()
```

当调用关闭端点并调用取消函数时，上下文将完成。我们可以等待该事件，然后使用具有超时的另一个上下文调用关闭方法：

```go
select {
case <-ctx.Done():
    ctx, canc := context.WithTimeout(context.Background(), time.Second*5)
    defer canc()
    if err := server.Shutdown(ctx); err != nil {
        log.Fatalln("Shutdown:", err)
    } else {
        log.Println("Shutdown:", "ok")
    }
}
```

这将允许我们在超时内有效地终止服务器，之后将以错误终止。

# 传递值

服务器中上下文的另一个用法是在不同的 HTTP 处理程序之间传播值和取消。让我们看一个例子，每个请求都有一个整数类型的唯一密钥。我们将使用一对类似于使用整数的值的函数。生成新密钥将使用`atomic`完成：

```go
type keyType struct{}

var key = &keyType{}

var counter int32

func WithKey(ctx context.Context) context.Context {
    return context.WithValue(ctx, key, atomic.AddInt32(&counter, 1))
}

func GetKey(ctx context.Context) (int32, bool) {
    v := ctx.Value(key)
    if v == nil {
        return 0, false
    }
    return v.(int32), true
}
```

现在，我们可以定义另一个函数，它接受任何 HTTP 处理程序，并在必要时创建上下文，并将密钥添加到其中：

```go

func AssignKeyHandler(h http.Handler) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        ctx := r.Context()
        if ctx == nil {
            ctx = context.Background()
        }
        if _, ok := GetKey(ctx); !ok {
            ctx = WithKey(ctx)
        }
        h.ServeHTTP(w, r.WithContext(ctx))
    }
}
```

通过这样做，我们可以定义一个非常简单的处理程序，用于在特定根目录下提供文件。此函数将使用上下文中的键正确记录信息。它还将在尝试提供文件之前检查文件是否存在：

```go
func ReadFileHandler(root string) http.HandlerFunc {
    root = filepath.Clean(root)
    return func(w http.ResponseWriter, r *http.Request) {
        k, _ := GetKey(r.Context())
        path := filepath.Join(root, r.URL.Path)
        log.Printf("[%d] requesting path %s", k, path)
        if !strings.HasPrefix(path, root) {
            http.Error(w, "not found", http.StatusNotFound)
            log.Printf("[%d] unauthorized %s", k, path)
            return
        }
        if stat, err := os.Stat(path); err != nil || stat.IsDir() {
            http.Error(w, "not found", http.StatusNotFound)
            log.Printf("[%d] not found %s", k, path)
            return
        }
        http.ServeFile(w, r, path)
        log.Printf("[%d] ok: %s", k, path)
    }
}
```

我们可以将这些处理程序组合起来，以便从不同文件夹（如主目录用户或临时目录）提供内容：

```go
home, err := os.UserHomeDir()
if err != nil {
    log.Fatal(err)
}
tmp := os.TempDir()
mux := http.NewServeMux()
server := http.Server{
    Addr: ":3000",
    Handler: mux,
}

mux.Handle("/tmp/", http.StripPrefix("/tmp/", AssignKeyHandler(ReadFileHandler(tmp))))
mux.Handle("/home/", http.StripPrefix("/home/", AssignKeyHandler(ReadFileHandler(home))))
if err := server.ListenAndServe(); err != nil {
    if err != http.ErrServerClosed {
        log.Fatal(err)
    }
}
```

我们使用`http.StipPrefix`来删除路径的第一部分并获取相对路径，并将其传递给下面的处理程序。生成的服务器将使用上下文在处理程序之间传递键值——这允许我们创建另一个类似的处理程序，并使用`AssignKeyHandler`函数来包装处理程序，并使用`GetKey(r.Context())`来访问处理程序内部的键。

# TCP 拨号

网络包提供了与上下文相关的功能，比如在拨号或监听传入连接时取消拨号。它允许我们在拨号连接时使用上下文的超时和取消功能。

# 取消连接

为了测试在 TCP 连接中使用上下文的用法，我们可以创建一个带有 TCP 服务器的 goroutine，在开始监听之前等待一段时间：

```go
addr := os.Args[1]
go func() {
    time.Sleep(time.Second)
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        log.Fatalln("Listener:", addr, err)
    }
    c, err := listener.Accept()
    if err != nil {
        log.Fatalln("Listener:", addr, err)
    }
    defer c.Close()
}()
```

我们可以使用一个比服务器等待时间更短的超时上下文。我们必须使用`net.Dialer`来在拨号操作中使用上下文：

```go
ctx, canc := context.WithTimeout(context.Background(),   
    time.Millisecond*100)
defer canc()
conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", os.Args[1])
if err != nil {
    log.Fatalln("-> Connection:", err)
}
log.Println("-> Connection to", os.Args[1])
conn.Close()
```

该应用程序将尝试连接一小段时间，但最终在上下文过期时放弃，返回一个错误。

在想要从一系列端点建立单个连接的情况下，上下文取消将是一个完美的用例。所有连接尝试将共享相同的上下文，并且正确拨号的第一个连接将调用取消，停止其他尝试。我们将创建一个单个服务器，它正在监听我们将尝试拨打的地址之一：

```go
list := []string{
    "localhost:9090",
    "localhost:9091",
    "localhost:9092",
}
go func() {
    listener, err := net.Listen("tcp", list[0])
    if err != nil {
        log.Fatalln("Listener:", list[0], err)
    }
    time.Sleep(time.Second * 5)
    c, err := listener.Accept()
    if err != nil {
        log.Fatalln("Listener:", list[0], err)
    }
    defer c.Close()
}()
```

然后，我们可以尝试拨打所有三个地址，并在其中一个连接时立即取消上下文。我们将使用`WaitGroup`与 goroutines 的结束进行同步：

```go
ctx, canc := context.WithTimeout(context.Background(), time.Second*10)
defer canc()
wg := sync.WaitGroup{}
wg.Add(len(list))
for _, addr := range list {
    go func(addr string) {
        defer wg.Done()
        conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
        if err != nil {
            log.Println("-> Connection:", err)
            return
        }
        log.Println("-> Connection to", addr, "cancelling context")
        canc()
        conn.Close()
    }(addr)
}
wg.Wait()
```

在此程序的输出中，我们将看到一个连接成功，然后是其他尝试的取消错误。

# 数据库操作

在本书中我们不会讨论`sql/database`包，但为了完整起见，值得一提的是它也使用了上下文。它的大部分操作都有相应的上下文对应，例如：

+   开始一个新的事务

+   执行查询

+   对数据库进行 ping

+   准备查询

这就是标准库中使用上下文的包的内容。接下来，我们将尝试使用上下文构建一个包，以允许该包的用户取消请求。

# 实验性包

实验包中一个值得注意的例子使用了上下文，我们已经看过了——信号量。现在我们对上下文的用途有了更好的理解，很明显为什么获取操作也需要一个上下文作为参数。

在创建应用程序时，我们可以提供带有超时或取消的上下文，并相应地采取行动：

```go
func main() {
    s := semaphore.NewWeighted(int64(5))
    ctx, canc := context.WithTimeout(context.Background(), time.Second)
    defer canc()
    wg := sync.WaitGroup{}
    wg.Add(20)
    for i := 0; i < 20; i++ {
        go func(i int) {
            defer wg.Done()
            if err := s.Acquire(ctx, 1); err != nil {
                fmt.Println(i, err)
                return
            }
            go func(i int) {
                fmt.Println(i)
                time.Sleep(time.Second / 2)
                s.Release(1)
            }(i)
        }(i)
    }
    wg.Wait()
}
```

运行此应用程序将显示，信号量在第一秒被获取，但之后上下文过期，所有剩余操作都失败了。

# 应用程序中的上下文

如果包或应用程序具有可能需要很长时间并且用户可以取消的操作，或者应该具有超时或截止日期等时间限制，那么`context.Context`是集成到其中的完美工具。

# 要避免的事情

尽管 Go 团队已经非常清楚地定义了上下文的范围，但开发人员一直以各种方式使用它——有些方式不太正统。让我们看看其中一些以及有哪些替代方案，而不是求助于上下文。

# 错误的键类型

避免的第一个做法是使用内置类型作为键。这是有问题的，因为它们可以被覆盖，因为具有相同内置值的两个接口被认为是相同的，如下例所示：

```go
func main() {
    var a interface{} = "request-id"
    var b interface{} = "request-id"
    fmt.Println(a == b)

    ctx := context.Background()
    ctx = context.WithValue(ctx, a, "a")
    ctx = context.WithValue(ctx, b, "b")
    fmt.Println(ctx.Value(a), ctx.Value(b))
}
```

完整的示例在这里可用：[`play.golang.org/p/2W3noYQP5eh`](https://play.golang.org/p/2W3noYQP5eh)。

第一个打印指令输出`true`，由于键是按值比较的，第二个赋值遮蔽了第一个，导致两个键的值相同。解决这个问题的一个潜在方法是使用空结构自定义类型，或者使用内置值的未导出指针。

# 传递参数

可能会发生这样的情况，你需要通过一系列函数调用长途跋涉。一个非常诱人的解决方案是使用上下文来存储该值，并且只在需要它的函数中调用它。通常不是一个好主意隐藏应该显式传递的必需参数。这会导致代码不够可读，因为它不会清楚地表明什么影响了某个函数的执行。

将函数传递到堆栈下仍然要好得多。如果参数列表变得太长，那么它可以被分组到一个或多个结构中，以便更易读。

让我们来看看以下函数：

```go
func SomeFunc(ctx context.Context, 
    name, surname string, age int, 
    resourceID string, resourceName string) {}
```

参数可以按以下方式分组：

```go
type User struct {
    Name string
    Surname string
    Age int
}

type Resource struct {
    ID string
    Name string
}

func SomeFunc(ctx context.Context, u User, r Resource) {}
```

# 可选参数

上下文应该用于传递可选参数，并且还用作一种类似于 Python `kwargs` 或 JavaScript `arguments` 的万能工具。将上下文用作行为的替代品可能会导致非常严重的问题，因为它可能导致变量的遮蔽，就像我们在`context.WithValue`的示例中看到的那样。

这种方法的另一个重大缺点是隐藏发生的事情，使代码更加晦涩。当涉及可选值时，更好的方法是使用指向结构参数的指针 - 这允许您完全避免传递结构与`nil`。

假设你有以下代码：

```go
// This function has two mandatory args and 4 optional ones
func SomeFunc(ctx context.Context, arg1, arg2 int, 
    opt1, opt2, opt3, opt4 string) {}
```

通过使用`Optional`，你会得到这样的东西：

```go
type Optional struct {
    Opt1 string
    Opt2 string
    Opt3 string
    Opt4 string
}

// This function has two mandatory args and 4 optional ones
func SomeFunc(ctx context.Context, arg1, arg2 int, o *Optional) {}
```

# 全局变量

一些全局变量可以存储在上下文中，以便它们可以通过一系列函数调用传递。这通常不是一个好的做法，因为全局变量在应用程序的每个点都可用，因此使用上下文来存储和调用它们是毫无意义的，而且是资源和性能的浪费。如果您的包有一些全局变量，您可以使用我们在第十二章中看到的 Singleton 模式，*使用 sync 和 atomic 进行同步*，允许从包或应用程序的任何点访问它们。

# 使用上下文构建服务

我们现在将专注于如何创建支持上下文使用的包。这将帮助我们整合到目前为止学到的有关并发性的知识。我们将尝试创建一个并发文件搜索，使用通道、goroutine、同步和上下文。

# 主接口和用法

包的签名将包括上下文、根文件夹、搜索项和一对可选参数：

+   **在内容中搜索**：将在文件内容中查找字符串，而不是名称

+   **排除列表**：不会搜索具有所选名称/名称的文件

该函数看起来可能是这样的：

```go
type Options struct {
    Contents bool
    Exclude []string
}

func FileSearch(ctx context.Context, root, term string, o *Options)
```

由于它应该是一个并发函数，返回类型可以是结果的通道，它可以是错误，也可以是文件中一系列匹配项。由于我们可以搜索内容的名称，后者可能有多个匹配项：

```go
type Result struct {
    Err error
    File string
    Matches []Match
}

type Match struct {
    Line int
    Text string
}
```

前一个函数将返回一个只接收的`Result`类型的通道：

```go
func FileSearch(ctx context.Context, root, term string, o *Options) <-chan Result
```

在这里，这个函数将继续从通道接收值，直到它被关闭：

```go
for r := range FileSearch(ctx, directory, searchTerm, options) {
    if r.Err != nil {
        fmt.Printf("%s - error: %s\n", r.File, r.Err)
        continue
    }
    if !options.Contents {
        fmt.Printf("%s - match\n", r.File)
        continue
    }
    fmt.Printf("%s - matches:\n", r.File)
    for _, m := range r.Matches {
        fmt.Printf("\t%d:%s\n", m.Line, m.Text)
    }
}
```

# 出口和入口点

结果通道应该由上下文的取消或搜索结束来关闭。由于通道不能被关闭两次，我们可以使用`sync.Once`来避免第二次关闭通道。为了跟踪正在运行的 goroutines，我们可以使用`sync.Waitgroup`：

```go
ch, wg, once := make(chan Result), sync.WaitGroup{}, sync.Once{}
go func() {
    wg.Wait()
    fmt.Println("* Search done *")
    once.Do(func() {
        close(ch)
    })
}()
go func() {
    <-ctx.Done()
    fmt.Println("* Context done *")
    once.Do(func() {
        close(ch)
    })
}()
```

我们可以为每个文件启动一个 goroutine，这样我们可以定义一个私有函数，作为入口点，然后递归地用于子目录：

```go
func fileSearch(ctx context.Context, ch chan<- Result, wg *sync.WaitGroup, file, term string, o *Options)
```

主要导出的函数将首先向等待组添加一个值。然后，启动私有函数，将其作为异步进程启动：

```go
wg.Add(1)
go fileSearch(ctx, ch, &wg, root, term, o)
```

每个`fileSearch`应该做的最后一件事是调用`WaitGroup.Done`来标记当前文件的结束。

# 排除列表

私有函数将在完成使用`Done`方法之前减少等待组计数器。此外，它应该首先检查文件名，以便如果在排除列表中，可以跳过它：

```go
defer wg.Done()
_, name := filepath.Split(file)
if o != nil {
    for _, e := range o.Exclude {
        if e == name {
            return
        }
    }
}
```

如果不是这种情况，我们可以使用`os.Stat`来检查当前文件的信息，并且如果不成功，向通道发送错误。由于我们不能冒险通过向关闭的通道发送数据来引发恐慌，我们可以检查上下文是否完成，如果没有，发送错误：

```go
info, err := os.Stat(file)
if err != nil {
    select {
    case <-ctx.Done():
        return
    default:
        ch <- Result{File: file, Err: err}
    }
    return
}
```

# 处理目录

接收到的信息将告诉我们文件是否是目录。如果是目录，我们可以获取文件列表并处理错误，就像我们之前使用`os.Stat`一样。然后，如果上下文尚未完成，我们可以启动另一系列搜索，每个文件一个。以下代码总结了这些操作：

```go
if info.IsDir() {
    files, err := ioutil.ReadDir(file)
    if err != nil {
        select {
        case <-ctx.Done():
            return
        default:
            ch <- Result{File: file, Err: err}
        }
        return
    }
    select {
    case <-ctx.Done():
    default:
        wg.Add(len(files))
        for _, f := range files {
            go fileSearch(ctx, ch, wg, filepath.Join(file, 
        f.Name()), term, o)
        }
    }
    return
}
```

# 检查文件名和内容

如果文件是常规文件而不是目录，我们可以比较文件名或其内容，具体取决于指定的选项。检查文件名非常容易：

```go
if o == nil || !o.Contents {
    if name == term {
        select {
        case <-ctx.Done():
        default:
            ch <- Result{File: file}
        }
    }
    return
}
```

如果我们正在搜索内容，我们应该打开文件：

```go
f, err := os.Open(file)
if err != nil {
    select {
    case <-ctx.Done():
    default:
        ch <- Result{File: file, Err: err}
    }
    return
}
defer f.Close()
```

然后，我们可以逐行读取文件以搜索所选的术语。如果在读取文件时上下文过期，我们将停止所有操作：

```go
scanner, matches, line := bufio.NewScanner(f), []Match{}, 1
for scanner.Scan() {
    select {
    case <-ctx.Done():
        break
    default:
        if text := scanner.Text(); strings.Contains(text, term) {
            matches = append(matches, Match{Line: line, Text: text})
        }
        line++
    }
}
```

最后，我们可以检查扫描器的错误。如果没有错误并且搜索有结果，我们可以将所有匹配项发送到输出通道：

```go
select {
case <-ctx.Done():
    break
default:
    if err := scanner.Err(); err != nil {
        ch <- Result{File: file, Err: err}
        return
    }
    if len(matches) != 0 {
        ch <- Result{File: file, Matches: matches}
    }
}
```

不到 200 行的代码中，我们创建了一个并发文件搜索函数，每个文件使用一个 goroutine。它利用通道发送结果和同步原语来协调操作。

# 总结

在本章中，我们看到了一个较新的包上下文的用途。我们看到`Context`是一个简单的接口，有四种方法，并且应该作为函数的第一个参数使用。它的主要作用是处理取消和截止日期，以同步并发操作，并为用户提供取消操作的功能。

我们看到了默认上下文`Background`和`TODO`不允许取消，但它们可以使用包的各种函数进行扩展，以添加超时或取消。我们还谈到了上下文在持有值方面的能力，以及应该小心使用这一点，以避免遮蔽和其他问题。

然后，我们深入研究了标准包，看看上下文已经被使用在哪里。这包括了请求的 HTTP 功能，它可以用于值、取消和超时，以及服务器关闭操作。我们还看到了 TCP 包如何允许我们以类似的方式使用它，并且列出了数据库包中允许我们使用上下文来取消它们的操作。

在使用上下文构建自己的功能之前，我们先了解了一些应该避免的用法，从使用错误类型的键到使用上下文传递应该在函数或方法签名中的值。然后，我们继续创建一个函数，用于搜索文件和内容，利用了我们从前三章学到的并发知识。

下一章将通过展示最常见的 Go 并发模式及其用法来结束本书的并发部分。这将使我们能够将迄今为止学到的关于并发的所有知识放在一些非常常见和有效的配置中。

# 问题

1.  在 Go 中上下文是什么？

1.  取消、截止时间和超时之间有什么区别？

1.  在使用上下文传递值时，有哪些最佳实践？

1.  哪些标准包已经使用了上下文？
