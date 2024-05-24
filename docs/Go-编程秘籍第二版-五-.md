# Go 编程秘籍第二版（五）

> 原文：[`zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0`](https://zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：测试 Go 代码

这一章将与之前的章节不同；这一章将专注于测试和测试方法。Go 提供了出色的测试支持。但是，对于来自更动态语言的开发人员来说，理解它可能会有困难，因为猴子补丁和模拟相对来说比较简单。

Go 测试鼓励为您的代码使用特定的结构。特别是，测试和模拟接口非常简单并且得到了很好的支持。某些类型的代码可能更难测试。例如，对于使用包级全局变量的代码、尚未抽象为接口的地方以及具有非导出变量或方法的结构，测试可能更加困难。本章将分享一些测试 Go 代码的示例。

在本章中，我们将涵盖以下示例：

+   使用标准库进行模拟

+   使用 Mockgen 包来模拟接口

+   使用表驱动测试来提高覆盖率

+   使用第三方测试工具

+   使用 Go 进行行为测试

# 技术要求

为了继续本章中的所有示例，根据以下步骤配置您的环境：

1.  从[`golang.org/doc/install`](https://golang.org/doc/install)下载并在您的操作系统上安装 Go 1.12.6 或更高版本。

1.  打开一个终端或控制台应用程序，然后创建并导航到一个项目目录，例如`~/projects/go-programming-cookbook`。所有代码将从该目录运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，您可以选择从该目录中工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 使用标准库进行模拟

在 Go 中，模拟通常意味着使用测试版本实现一个接口，允许您从测试中控制运行时行为。它也可能指模拟函数和方法，对于这一点，我们将在本示例中探讨另一个技巧。这个技巧使用了在[`play.golang.org/p/oLF1XnRX3C`](https://play.golang.org/p/oLF1XnRX3C)定义的`Patch`和`Restore`函数。

一般来说，最好组合代码，以便您可以经常使用接口，并且代码是由小的、可测试的块组成的。包含大量分支条件或深度嵌套逻辑的代码可能很难测试，测试结果往往更加脆弱。这是因为开发人员需要在测试中跟踪更多的模拟对象、补丁、返回值和状态。

# 如何做...

这些步骤涵盖了编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter9/mocking`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/mocking 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/mocking    
```

1.  创建一个名为`mock.go`的文件，内容如下：

```go
        package mocking

        // DoStuffer is a simple interface
        type DoStuffer interface {
            DoStuff(input string) error
        }
```

1.  创建一个名为`patch.go`的文件，内容如下：

```go
        package mocking

        import "reflect"

        // Restorer holds a function that can be used
        // to restore some previous state.
        type Restorer func()

        // Restore restores some previous state.
        func (r Restorer) Restore() {
            r()
        }

        // Patch sets the value pointed to by the given destination to 
        // the given value, and returns a function to restore it to its 
        // original value. The value must be assignable to the element 
        //type of the destination.
        func Patch(dest, value interface{}) Restorer {
            destv := reflect.ValueOf(dest).Elem()
            oldv := reflect.New(destv.Type()).Elem()
            oldv.Set(destv)
            valuev := reflect.ValueOf(value)
            if !valuev.IsValid() {
                // This isn't quite right when the destination type is 
                // not nilable, but it's better than the complex 
                // alternative.
                valuev = reflect.Zero(destv.Type())
            }
            destv.Set(valuev)
            return func() {
                destv.Set(oldv)
            }
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package mocking
        import "errors"
        var ThrowError = func() error {
            return errors.New("always fails")
        }

        func DoSomeStuff(d DoStuffer) error {

            if err := d.DoStuff("test"); err != nil {
                return err
            }

            if err := ThrowError(); err != nil {
                return err
            }

            return nil
        }
```

1.  创建一个名为`mock_test.go`的文件，内容如下：

```go
        package mocking
        type MockDoStuffer struct {
            // closure to assist with mocking
            MockDoStuff func(input string) error
        }
        func (m *MockDoStuffer) DoStuff(input string) error {
            if m.MockDoStuff != nil {
                return m.MockDoStuff(input)
            }
            // if we don't mock, return a common case
            return nil
        }
```

1.  创建一个名为`exec_test.go`的文件，内容如下：

```go
        package mocking
        import (
            "errors"
            "testing"
        )

        func TestDoSomeStuff(t *testing.T) {
            tests := []struct {
                name       string
                DoStuff    error
                ThrowError error
                wantErr    bool
            }{
                {"base-case", nil, nil, false},
                {"DoStuff error", errors.New("failed"), nil, true},
                {"ThrowError error", nil, errors.New("failed"), true},
            }
            for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                    // An example of mocking an interface
                    // with our mock struct
                    d := MockDoStuffer{}
                    d.MockDoStuff = func(string) error {
                    return tt.DoStuff }

                   // mocking a function that is declared as a variable
                   // will not work for func A(),
                   // must be var A = func()
                   defer Patch(&ThrowError, func() error { return 
                   tt.ThrowError }).Restore()

                  if err := DoSomeStuff(&d); (err != nil) != tt.wantErr 
                  {
                      t.Errorf("DoSomeStuff() error = %v, 
                      wantErr %v", err, tt.wantErr)
                  }
                })
            }
        }
```

1.  为剩余的函数填写测试，并进入上一级目录运行`go test`。确保所有测试都通过：

```go
$go test
PASS
ok github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/mocking 0.006s 
```

1.  `go.mod`文件可能会被更新，顶级示例目录中现在应该存在`go.sum`文件。

# 工作原理...

这个示例演示了如何模拟接口以及已声明为变量的函数。还有一些库可以直接模拟这些已声明函数的补丁/恢复，但它们绕过了很多 Go 的类型安全来实现这一功能。如果您需要对外部包中的函数进行补丁，可以使用以下技巧：

```go
// Whatever package you wanna patch
import "github.com/package" 

// This is patchable using the method described in this recipe
var packageDoSomething = package.DoSomething
```

对于这个示例，我们首先设置我们的测试并使用表驱动测试。关于这种技术有很多文献，比如[`github.com/golang/go/wiki/TableDrivenTests`](https://github.com/golang/go/wiki/TableDrivenTests)，我建议进一步探索。一旦我们设置了测试，我们就为我们的模拟函数选择输出。为了模拟我们的接口，我们的模拟对象定义了可以在运行时重写的闭包。补丁/恢复技术被应用于在每次循环后更改我们的全局函数并恢复它。这要归功于`t.Run`，它为测试的每次循环设置了一个新函数。

# 使用 Mockgen 包来模拟接口

前面的示例使用了我们的自定义模拟对象。当您使用大量接口时，编写这些内容可能会变得繁琐且容易出错。这是生成代码非常有意义的地方。幸运的是，有一个名为`github.com/golang/mock/gomock`的包，它提供了模拟对象的生成，并为我们提供了一个非常有用的库，可以与接口测试一起使用。

这个示例将探讨`gomock`的一些功能，并涵盖在何时、何地以及如何使用和生成模拟对象的权衡。

# 准备工作

根据以下步骤配置您的环境：

1.  请参阅本章开头的*技术要求*部分。

1.  运行`go get github.com/golang/mock/mockgen`命令。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter9/mockgen`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/mockgen 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/mockgen    
```

1.  创建一个名为`interface.go`的文件，内容如下：

```go
        package mockgen

        // GetSetter implements get a set of a
        // key value pair
        type GetSetter interface {
            Set(key, val string) error
            Get(key string) (string, error)
        }
```

1.  创建一个名为`internal`的目录。

1.  运行`mockgen -destination internal/mocks.go -package internal github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/mockgen GetSetter`命令。这将创建一个名为`internal/mocks.go`的文件。

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package mockgen

        // Controller is a struct demonstrating
        // one way to initialize interfaces
        type Controller struct {
            GetSetter
        }

        // GetThenSet checks if a value is set. If not
        // it sets it.
        func (c *Controller) GetThenSet(key, value string) error {
            val, err := c.Get(key)
            if err != nil {
                return err
            }

            if val != value {
                return c.Set(key, value)
            }
            return nil
        }
```

1.  创建一个名为`interface_test.go`的文件，内容如下：

```go
        package mockgen

        import (
            "errors"
            "testing"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter9/mockgen/internal"
            "github.com/golang/mock/gomock"
        )

        func TestExample(t *testing.T) {
            ctrl := gomock.NewController(t)
            defer ctrl.Finish()

            mockGetSetter := internal.NewMockGetSetter(ctrl)

            var k string
            mockGetSetter.EXPECT().Get("we can put anything 
            here!").Do(func(key string) {
                k = key
            }).Return("", nil)

            customError := errors.New("failed this time")

            mockGetSetter.EXPECT().Get(gomock.Any()).Return("", 
            customError)

            if _, err := mockGetSetter.Get("we can put anything 
            here!"); err != nil {
                t.Errorf("got %#v; want %#v", err, nil)
            }
            if k != "we can put anything here!" {
                t.Errorf("bad key")
            }

            if _, err := mockGetSetter.Get("key"); err == nil {
                t.Errorf("got %#v; want %#v", err, customError)
            }
        }
```

1.  创建一个名为`exec_test.go`的文件，内容如下：

```go
        package mockgen

        import (
            "errors"
            "testing"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter9/mockgen/internal"
            "github.com/golang/mock/gomock"
        )

        func TestController_Set(t *testing.T) {
            tests := []struct {
                name string
                getReturnVal string
                getReturnErr error
                setReturnErr error
                wantErr bool
            }{
                {"get error", "value", errors.New("failed"), nil, 
                true},
                {"value match", "value", nil, nil, false},
                {"no errors", "not set", nil, nil, false},
                {"set error", "not set", nil, errors.New("failed"),
                true},
            }
            for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                    ctrl := gomock.NewController(t)
                    defer ctrl.Finish()

                    mockGetSetter := internal.NewMockGetSetter(ctrl)
                    mockGetSetter.EXPECT().Get("key").AnyTimes()
                    .Return(tt.getReturnVal, tt.getReturnErr)
                    mockGetSetter.EXPECT().Set("key", 
                    gomock.Any()).AnyTimes().Return(tt.setReturnErr)

                    c := &Controller{
                        GetSetter: mockGetSetter,
                    }
                    if err := c.GetThenSet("key", "value"); (err != 
                    nil) != tt.wantErr {
                        t.Errorf("Controller.Set() error = %v, wantErr 
                        %v", err, tt.wantErr)
                    }
                })
             }
        }
```

1.  为剩余的函数填写测试，返回上一级目录，并运行`go test`。确保所有测试都通过。

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶级配方目录中。

# 工作原理...

生成的模拟对象允许测试指定预期的参数、函数将被调用的次数以及返回的内容。它们还允许我们设置额外的工件。例如，如果原始函数具有类似的工作流程，我们可以直接写入通道。`interface_test.go`文件展示了在调用模拟对象时使用一些示例。通常，测试看起来更像`exec_test.go`，在这里我们希望拦截实际代码执行的接口函数调用，并在测试时更改它们的行为。

`exec_test.go`文件还展示了如何在表驱动测试环境中使用模拟对象。`Any()`函数表示模拟函数可以被调用零次或多次，这对于代码提前终止的情况非常有用。

在这个示例中演示的最后一个技巧是将模拟对象放入`internal`包中。当您需要模拟在您自己之外的包中声明的函数时，这是很有用的。这允许这些方法在`non _test.go`文件中定义，但它们对您的库的用户不可见，因为他们无法从内部包导入。通常，最容易的方法是将模拟对象放入与您当前编写的测试相同的包名的`_test.go`文件中。

# 使用表驱动测试来提高覆盖率

这个示例将演示如何编写表驱动测试、收集测试覆盖率并改进它的过程。它还将使用`github.com/cweill/gotests`包来生成测试。如果您已经下载了其他章节的测试代码，这些内容应该会很熟悉。通过结合这个示例和前两个示例，您应该能够在所有情况下通过一些工作实现 100%的测试覆盖率。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter9/coverage`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/coverage 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/coverage    
```

1.  创建一个名为`coverage.go`的文件，内容如下：

```go
        package main

        import "errors"

        // Coverage is a simple function with some branching conditions
        func Coverage(condition bool) error {
            if condition {
                return errors.New("condition was set")
            }
            return nil
        }
```

1.  运行`gotests -all -w`命令。

1.  这将生成一个名为`coverage_test.go`的文件，内容如下：

```go
        package main

        import "testing"

        func TestCoverage(t *testing.T) {
            type args struct {
                condition bool
            }
            tests := []struct {
                name string
                args args
                wantErr bool
            }{
                // TODO: Add test cases.
            }
            for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                    if err := Coverage(tt.args.condition); (err != nil) 
                    != tt.wantErr {
                        t.Errorf("Coverage() error = %v, wantErr %v", 
                        err, tt.wantErr)
                    }
                })
            }
        }
```

1.  使用以下内容填写`TODO`部分：

```go
        {"no condition", args{true}, true},
```

1.  运行`go test -cover`命令，您将看到以下输出：

```go
$ go test -cover 
PASS
coverage: 66.7% of statements
ok github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/coverage 0.007s
```

1.  将以下内容添加到`TODO`部分：

```go
        {"condition", args{false}, false},
```

1.  运行`go test -cover`命令，您将看到以下输出：

```go
$ go test -cover 
PASS
coverage: 100.0% of statements
ok github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/coverage 0.007s
```

1.  运行以下命令：

```go
$ go test -coverprofile=cover.out 
$ go tool cover -html=cover.out -o coverage.html
```

1.  在浏览器中打开`coverage.html`文件，以查看图形覆盖报告。

1.  `go.mod`文件可能会被更新，顶级示例目录中现在应该存在`go.sum`文件。

# 它是如何工作的...

`go test -cover`命令是基本的 Go 安装中自带的。它可以用来收集您的 Go 应用程序的覆盖报告。此外，它还可以输出覆盖度指标和 HTML 覆盖报告。这个工具通常被其他工具包装，下一个示例将介绍这些内容。这些表驱动测试样式在[`github.com/golang/go/wiki/TableDrivenTests`](https://github.com/golang/go/wiki/TableDrivenTests)中有介绍，是一种优秀的方式，可以处理许多情况而不需要编写大量额外的代码。

这个示例首先通过自动生成测试代码，然后根据需要填写测试用例来帮助创建更多的覆盖。唯一特别棘手的时候是当您调用非变量函数或方法时。例如，让`gob.Encode()`返回一个错误以增加测试覆盖率可能会很棘手。使用本章的*使用标准库进行模拟*示例中描述的方法，并使用`var gobEncode = gob.Encode`来允许打补丁，也可能看起来有些古怪。因此，很难主张 100%的测试覆盖率，而是主张集中测试外部接口的广泛性——也就是测试输入和输出的许多变化，有时，正如我们将在本章的*使用 Go 进行行为测试*示例中看到的那样，模糊测试可能会变得有用。

# 使用第三方测试工具

有许多有用的 Go 测试工具：可以更轻松地了解每个函数级别的代码覆盖情况的工具，可以实现断言以减少测试代码行数的工具，以及测试运行器。这个示例将介绍`github.com/axw/gocov`和`github.com/smartystreets/goconvey`包，以演示其中一些功能。根据您的需求，还有许多其他值得注意的测试框架。`github.com/smartystreets/goconvey`包支持断言和是一个测试运行器。在 Go 1.7 之前，这是最干净的方法来拥有带标签的子测试。

# 准备工作

根据以下步骤配置您的环境：

1.  请参考本章开头的*技术要求*部分。

1.  运行`go get github.com/axw/gocov/gocov`命令。

1.  运行`go get github.com/smartystreets/goconvey`命令。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter9/tools`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/tools 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/tools
```

1.  创建一个名为`funcs.go`的文件，内容如下：

```go
        package tools

        import (
            "fmt"
        )

        func example() error {
            fmt.Println("in example")
            return nil
        }

        var example2 = func() int {
            fmt.Println("in example2")
            return 10
        }
```

1.  创建一个名为`structs.go`的文件，内容如下：

```go
        package tools

        import (
            "errors"
            "fmt"
        )

        type c struct {
            Branch bool
        }

        func (c *c) example3() error {
            fmt.Println("in example3")
            if c.Branch {
                fmt.Println("branching code!")
                return errors.New("bad branch")
            }
            return nil
        }
```

1.  创建一个名为`funcs_test.go`的文件，内容如下：

```go
        package tools

        import (
            "testing"

            . "github.com/smartystreets/goconvey/convey"
        )

        func Test_example(t *testing.T) {
            tests := []struct {
                name string
            }{
                {"base-case"},
            }
            for _, tt := range tests {
                Convey(tt.name, t, func() {
                    res := example()
                    So(res, ShouldBeNil)
                })
            }
        }

        func Test_example2(t *testing.T) {
            tests := []struct {
                name string
            }{
                {"base-case"},
            }
            for _, tt := range tests {
                Convey(tt.name, t, func() {
                    res := example2()
                    So(res, ShouldBeGreaterThanOrEqualTo, 1)
                })
            }
        }
```

1.  创建一个名为`structs_test.go`的文件，内容如下：

```go
        package tools

        import (
            "testing"

            . "github.com/smartystreets/goconvey/convey"
        )

        func Test_c_example3(t *testing.T) {
            type fields struct {
                Branch bool
            }
            tests := []struct {
                name string
                fields fields
                wantErr bool
            }{
                {"no branch", fields{false}, false},
                {"branch", fields{true}, true},
            }
            for _, tt := range tests {
                Convey(tt.name, t, func() {
                    c := &c{
                        Branch: tt.fields.Branch,
                    }
                    So((c.example3() != nil), ShouldEqual, tt.wantErr)
                })
            }
        }
```

1.  运行`gocov test | gocov report`命令，你会看到以下输出：

```go
$ gocov test | gocov report
ok github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/tools 0.006s 
coverage: 100.0% of statements

github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/tools/struct.go 
c.example3 100.00% (5/5)
github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/tools/funcs.go example 
100.00% (2/2)
github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/tools/funcs.go @12:16 
100.00% (2/2)
github.com/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/chapter9/tools ---------- 
100.00% (9/9)

Total Coverage: 100.00% (9/9)
```

1.  运行`goconvey`命令，它将打开一个看起来像这样的浏览器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-cb-2e/img/c786af09-2ea5-4497-931c-aa087f5fa85d.png)

1.  确保所有测试都通过。

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶级配方目录中。

# 它是如何工作的...

本教程演示了如何将`goconvey`命令与你的测试连接起来。`Convey`关键字基本上取代了`t.Run`，并在`goconvey`Web UI 中添加了额外的标签，但它的行为略有不同。如果你有嵌套的`Convey`块，它们总是按顺序重新执行，如下所示：

```go
Convey("Outer loop", t, func(){
    a := 1
    Convey("Inner loop", t, func() {
        a = 2
    })
    Convey ("Inner loop2", t, func(){
        fmt.Println(a)
     })
})
```

使用`goconvey`命令，上面的代码将打印`1`。如果我们使用内置的`t.Run`，它将打印`2`。换句话说，Go 的`t.Run`测试是顺序运行的，永远不会重复。这种行为对于将设置代码放入外部`Convey`块非常有用，但如果你必须同时使用，记住这个区别是很重要的。

当使用`Convey`断言时，在 Web UI 和额外的统计信息中会有成功的勾号。它还可以将检查的大小减少到一行，甚至可以创建自定义断言。

如果你保持`goconvey`Web 界面打开并打开通知，当你保存代码时，测试将自动运行，并且你将收到有关覆盖率增加或减少以及构建失败的通知。

所有三个工具断言、测试运行器和 Web UI 都可以独立或一起使用。

`gocov`工具在提高测试覆盖率时非常有用。它可以快速识别缺乏覆盖的函数，并帮助你深入了解你的覆盖报告。此外，`gocov`还可以用来生成一个随 Go 代码一起提供的替代 HTML 报告，使用`github.com/matm/gocov-html`包。

# 使用 Go 进行行为测试

行为测试或集成测试是实现端到端黑盒测试的一种好方法。这种类型测试的一个流行框架是 Cucumber（[`cucumber.io/`](https://cucumber.io/)），它使用 Gherkin 语言来描述测试的步骤，然后在代码中实现这些步骤。Go 也有一个 Cucumber 库（`github.com/DATA-DOG/godog`）。本教程将使用`godog`包来编写行为测试。

# 准备就绪

根据以下步骤配置你的环境：

1.  请参考本章开头的*技术要求*部分。

1.  运行`go get github.com/DATA-DOG/godog/cmd/godog`命令。

# 如何做...

这些步骤涵盖了编写和运行你的应用程序：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter9/bdd`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/bdd 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter9/bdd
```

1.  创建一个名为`handler.go`的文件，内容如下：

```go
        package bdd

        import (
            "encoding/json"
            "fmt"
            "net/http"
        )

        // HandlerRequest will be json decoded
        // into by Handler
        type HandlerRequest struct {
            Name string `json:"name"`
        }

        // Handler takes a request and renders a response
        func Handler(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            if r.Method != http.MethodPost {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
            }

            dec := json.NewDecoder(r.Body)
            var req HandlerRequest
            if err := dec.Decode(&req); err != nil {
                w.WriteHeader(http.StatusBadRequest)
                return
            }

            w.WriteHeader(http.StatusOK)
            w.Write([]byte(fmt.Sprintf("BDD testing %s", req.Name)))
        }
```

1.  创建一个名为`features`的新目录，并创建一个名为`features/handler.go`的文件，内容如下：

```go
        Feature: Bad Method
         Scenario: Good request
         Given we create a HandlerRequest payload with:
            | reader |
            | coder |
            | other |
         And we POST the HandlerRequest to /hello
         Then the response code should be 200
         And the response body should be:
            | BDD testing reader |
            | BDD testing coder |
            | BDD testing other |
```

1.  运行`godog`命令，你会看到以下输出：

```go
$ godog
.
1 scenarios (1 undefined)
4 steps (4 undefined)
89.062µs
.
```

1.  这将为你提供一个骨架来实现我们在特性文件中编写的测试；将它们复制到`handler_test.go`中并实现前两个步骤：

```go
        package bdd

        import (
            "bytes"
            "encoding/json"
            "fmt"
            "net/http/httptest"

            "github.com/DATA-DOG/godog"
            "github.com/DATA-DOG/godog/gherkin"
        )

        var payloads []HandlerRequest
        var resps []*httptest.ResponseRecorder

        func weCreateAHandlerRequestPayloadWith(arg1 
        *gherkin.DataTable) error {
            for _, row := range arg1.Rows {
                h := HandlerRequest{
                    Name: row.Cells[0].Value,
                }
                payloads = append(payloads, h)
            }
            return nil
        }

        func wePOSTTheHandlerRequestToHello() error {
            for _, p := range payloads {
                v, err := json.Marshal(p)
                if err != nil {
                    return err
                }
                w := httptest.NewRecorder()
                r := httptest.NewRequest("POST", "/hello", 
                bytes.NewBuffer(v))

                Handler(w, r)
                resps = append(resps, w)
            }
            return nil
        }
```

1.  运行`godog`命令，你会看到以下输出：

```go
$ godog
.
1 scenarios (1 pending)
4 steps (2 passed, 1 pending, 1 skipped)
.
```

1.  填写剩下的两个步骤：

```go
        func theResponseCodeShouldBe(arg1 int) error {
            for _, r := range resps {
                if got, want := r.Code, arg1; got != want {
                    return fmt.Errorf("got: %d; want %d", got, want)
                }
            }
            return nil
        }

        func theResponseBodyShouldBe(arg1 *gherkin.DataTable) error {
            for c, row := range arg1.Rows {
                b := bytes.Buffer{}
                b.ReadFrom(resps[c].Body)
                if got, want := b.String(), row.Cells[0].Value;
                got != want 
                {
                    return fmt.Errorf("got: %s; want %s", got, want)
                }
            }
            return nil
        }

        func FeatureContext(s *godog.Suite) {
            s.Step(`^we create a HandlerRequest payload with:$`, 
            weCreateAHandlerRequestPayloadWith)
            s.Step(`^we POST the HandlerRequest to /hello$`, 
            wePOSTTheHandlerRequestToHello)
            s.Step(`^the response code should be (d+)$`, 
            theResponseCodeShouldBe)
            s.Step(`^the response body should be:$`, 
            theResponseBodyShouldBe)
        }
```

1.  运行`godog`命令，你会看到以下输出：

```go
$ godog 
.
1 scenarios (1 passed)
4 steps (4 passed)
552.605µs
.
```

# 它是如何工作的...

Cucumber 框架非常适用于配对编程、端到端测试以及任何需要通过书面说明进行最佳沟通并且非技术人员可以理解的测试。一旦一个步骤被实现，通常可以在需要的任何地方重复使用它。如果您想要测试服务之间的集成，可以编写测试来使用实际的 HTTP 客户端，只要首先确保您的环境已设置为接收 HTTP 连接。

Datadog 对**行为驱动开发**（BDD）的实现缺少一些功能，如果您曾经使用过其他 Cucumber 框架，可能会期望这些功能，包括缺乏示例、在函数之间传递上下文，以及许多其他关键字。然而，这是一个很好的开始，通过在这个配方中使用一些技巧，比如使用全局变量来跟踪状态（并确保在场景之间清理这些全局变量），可以构建一个相当健壮的测试集。Datadog 测试包还使用了第三方测试运行器，因此无法与诸如`gocov`或`go test -cover`等包一起使用。


# 第十章：并行和并发

本章中的示例涵盖了工作池、异步操作的等待组以及`context`包的使用。并行和并发是 Go 语言最广告和推广的特性之一。本章将提供一些有用的模式，帮助您入门并了解这些特性。

Go 提供了使并行应用程序成为可能的原语。Goroutines 允许任何函数变成异步和并发的。通道允许应用程序与 Goroutines 建立通信。Go 语言中有一句著名的话是：“*不要通过共享内存进行通信；相反，通过通信共享内存*”，出自[`blog.golang.org/share-memory-by-communicating`](https://blog.golang.org/share-memory-by-communicating)。

在本章中，我们将涵盖以下示例：

+   使用通道和 select 语句

+   使用 sync.WaitGroup 执行异步操作

+   使用原子操作和互斥锁

+   使用上下文包

+   执行通道的状态管理

+   使用工作池设计模式

+   使用工作进程创建管道

# 技术要求

为了继续本章中的所有示例，请按照以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开终端或控制台应用程序，并创建并转到一个项目目录，例如`~/projects/go-programming-cookbook`。所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，（可选）从该目录中工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 使用通道和 select 语句

Go 通道与 Goroutines 结合使用，是异步通信的一等公民。当我们使用 select 语句时，通道变得特别强大。这些语句允许 Goroutine 智能地处理来自多个通道的请求。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/channels`的新目录，并转到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/channels 
```

您应该看到一个名为`go.mod`的文件，其中包含以下代码：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/channels    
```

1.  复制`~/projects/go-programming-cookbook-original/chapter10/channels`中的测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`sender.go`的文件，内容如下：

```go
        package channels

        import "time"

        // Sender sends "tick"" on ch until done is
        // written to, then it sends "sender done."
        // and exits
        func Sender(ch chan string, done chan bool) {
            t := time.Tick(100 * time.Millisecond)
            for {
                select {
                    case <-done:
                        ch <- "sender done."
                        return
                    case <-t:
                        ch <- "tick"
                }
            }
        }
```

1.  创建一个名为`printer.go`的文件，内容如下：

```go
        package channels

        import (
            "context"
            "fmt"
            "time"
        )

        // Printer will print anything sent on the ch chan
        // and will print tock every 200 milliseconds
        // this will repeat forever until a context is
        // Done, i.e. timed out or cancelled
        func Printer(ctx context.Context, ch chan string) {
            t := time.Tick(200 * time.Millisecond)
            for {
                select {
                  case <-ctx.Done():
                      fmt.Println("printer done.")
                      return
                  case res := <-ch:
                      fmt.Println(res)
                  case <-t:
                      fmt.Println("tock")
                }
            }
        }
```

1.  创建一个名为`example`的新目录，并转到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "context"
            "time"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter10/channels"
        )

        func main() {
            ch := make(chan string)
            done := make(chan bool)

            ctx := context.Background()
            ctx, cancel := context.WithCancel(ctx)
            defer cancel()

            go channels.Printer(ctx, ch)
            go channels.Sender(ch, done)

            time.Sleep(2 * time.Second)
            done <- true
            cancel()
            //sleep a bit extra so channels can clean up
            time.Sleep(3 * time.Second)
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您现在应该看到以下输出，但打印顺序可能会有所不同：

```go
$ go run main.go
tick
tock
tick
tick
tock
tick
tick
tock
tick
.
.
.
sender done.
printer done.
```

1.  `go.mod`文件可能会被更新，顶级示例目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

此示例演示了启动读取或写入通道的工作进程的两种方法，并且可能同时执行两者。当写入`done`通道或通过调用取消函数或超时取消`context`时，工作进程将终止。*使用上下文包*示例将更详细地介绍`context`包。

`main`包用于将各个函数连接在一起；由于这一点，可以设置多个成对，只要通道不共享。除此之外，可以有多个 Goroutines 监听同一个通道，我们将在*使用工作池设计模式*示例中探讨。

最后，由于 Goroutines 的异步性质，建立清理和终止条件可能会很棘手；例如，一个常见的错误是执行以下操作：

```go
select{
    case <-time.Tick(200 * time.Millisecond):
    //this resets whenever any other 'lane' is chosen
}
```

通过将`Tick`放在`select`语句中，可以防止这种情况发生。在`select`语句中也没有简单的方法来优先处理流量。

# 使用 sync.WaitGroup 执行异步操作

有时，异步执行一些操作并等待它们完成是有用的。例如，如果一个操作需要从多个 API 中提取信息并聚合该信息，那么将这些客户端请求异步化将会很有帮助。这个示例将探讨如何使用`sync.WaitGroup`来编排并行的非依赖任务。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/waitgroup`的新目录，并转到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/waitgroup 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/waitgroup    
```

1.  从`~/projects/go-programming-cookbook-original/chapter10/waitgroup`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`tasks.go`的文件，其中包含以下内容：

```go
        package waitgroup

        import (
            "fmt"
            "log"
            "net/http"
            "strings"
            "time"
        )

        // GetURL gets a url, and logs the time it took
        func GetURL(url string) (*http.Response, error) {
            start := time.Now()
            log.Printf("getting %s", url)
            resp, err := http.Get(url)
            log.Printf("completed getting %s in %s", url, 
            time.Since(start))
            return resp, err
        }

        // CrawlError is our custom error type
        // for aggregating errors
        type CrawlError struct {
            Errors []string
        }

        // Add adds another error
        func (c *CrawlError) Add(err error) {
            c.Errors = append(c.Errors, err.Error())
        }

        // Error implements the error interface
        func (c *CrawlError) Error() string {
            return fmt.Sprintf("All Errors: %s", strings.Join(c.Errors, 
            ","))
        }

        // Present can be used to determine if
        // we should return this
        func (c *CrawlError) Present() bool {
            return len(c.Errors) != 0
        }
```

1.  创建一个名为`process.go`的文件，其中包含以下内容：

```go
        package waitgroup

        import (
            "log"
            "sync"
            "time"
        )

        // Crawl collects responses from a list of urls
        // that are passed in. It waits for all requests
        // to complete before returning.
        func Crawl(sites []string) ([]int, error) {
            start := time.Now()
            log.Printf("starting crawling")
            wg := &sync.WaitGroup{}

            var resps []int
            cerr := &CrawlError{}
            for _, v := range sites {
                wg.Add(1)
                go func(v string) {
                    defer wg.Done()
                    resp, err := GetURL(v)
                    if err != nil {
                        cerr.Add(err)
                        return
                    }
                    resps = append(resps, resp.StatusCode)
                }(v)
            }
            wg.Wait()
            // we encountered a crawl error
            if cerr.Present() {
                return resps, cerr
            }
            log.Printf("completed crawling in %s", time.Since(start))
            return resps, nil
        }
```

1.  创建一个名为`example`的新目录，并转到该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter10/waitgroup"
        )

        func main() {
            sites := []string{
                "https://golang.org",
                "https://godoc.org",
                "https://www.google.com/search?q=golang",
            }

            resps, err := waitgroup.Crawl(sites)
            if err != nil {
                panic(err)
            }
            fmt.Println("Resps received:", resps)
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
2017/04/05 19:45:07 starting crawling
2017/04/05 19:45:07 getting https://www.google.com/search?
q=golang
2017/04/05 19:45:07 getting https://golang.org
2017/04/05 19:45:07 getting https://godoc.org
2017/04/05 19:45:07 completed getting https://golang.org in 
178.22407ms
2017/04/05 19:45:07 completed getting https://godoc.org in 
181.400873ms
2017/04/05 19:45:07 completed getting 
https://www.google.com/search?q=golang in 238.019327ms
2017/04/05 19:45:07 completed crawling in 238.191791ms
Resps received: [200 200 200]
```

1.  `go.mod`文件可能会更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

这个示例向您展示了如何在等待工作时使用`waitgroups`作为同步机制。实质上，`waitgroup.Wait()`将等待其内部计数器达到`0`。`waitgroup.Add(int)`方法将按输入的数量递增计数器，`waitgroup.Done()`将递减计数器`1`。因此，必须异步`Wait()`，而各种 Goroutines 标记`waitgroup`为`Done()`。

在这个示例中，我们在分派每个 HTTP 请求之前递增，然后调用 defer `wg.Done()`方法，这样我们就可以在 Goroutine 终止时递减。然后我们等待所有 Goroutines 完成，然后返回我们聚合的结果。

实际上，最好使用通道来传递错误和响应。

在执行此类异步操作时，您应该考虑诸如修改共享映射之类的事物的线程安全性。如果您记住这一点，`waitgroups`是等待任何类型的异步操作的有用功能。

# 使用原子操作和互斥

在诸如 Go 之类的语言中，您可以构建异步操作和并行性，考虑诸如线程安全之类的事情变得很重要。例如，同时从多个 Goroutines 访问映射是危险的。Go 在`sync`和`sync/atomic`包中提供了许多辅助工具，以确保某些事件仅发生一次，或者 Goroutines 可以在操作上进行序列化。

这个示例将演示使用这些包来安全地修改具有各种 Goroutines 的映射，并保持可以被多个 Goroutines 安全访问的全局序数值。它还将展示`Once.Do`方法，该方法可用于确保 Go 应用程序只执行一次某些操作，例如读取配置文件或初始化变量。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/atomic`的新目录，并转到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/atomic 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/atomic    
```

1.  从`~/projects/go-programming-cookbook-original/chapter10/atomic`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`map.go`的文件，内容如下：

```go
        package atomic

        import (
            "errors"
            "sync"
        )

        // SafeMap uses a mutex to allow
        // getting and setting in a thread-safe way
        type SafeMap struct {
            m map[string]string
            mu *sync.RWMutex
        }

        // NewSafeMap creates a SafeMap
        func NewSafeMap() SafeMap {
            return SafeMap{m: make(map[string]string), mu: 
            &sync.RWMutex{}}
        }

        // Set uses a write lock and sets the value given
        // a key
        func (t *SafeMap) Set(key, value string) {
            t.mu.Lock()
            defer t.mu.Unlock()

            t.m[key] = value
        }

        // Get uses a RW lock and gets the value if it exists,
        // otherwise an error is returned
        func (t *SafeMap) Get(key string) (string, error) {
            t.mu.RLock()
            defer t.mu.RUnlock()

            if v, ok := t.m[key]; ok {
                return v, nil
            }

            return "", errors.New("key not found")
        }
```

1.  创建一个名为`ordinal.go`的文件，内容如下：

```go
        package atomic

        import (
            "sync"
            "sync/atomic"
        )

        // Ordinal holds a global a value
        // and can only be initialized once
        type Ordinal struct {
            ordinal uint64
            once *sync.Once
        }

        // NewOrdinal returns ordinal with once
        // setup
        func NewOrdinal() *Ordinal {
            return &Ordinal{once: &sync.Once{}}
        }

        // Init sets the ordinal value
        // can only be done once
        func (o *Ordinal) Init(val uint64) {
            o.once.Do(func() {
                atomic.StoreUint64(&o.ordinal, val)
            })
        }

        // GetOrdinal will return the current
        // ordinal
        func (o *Ordinal) GetOrdinal() uint64 {
            return atomic.LoadUint64(&o.ordinal)
        }

        // Increment will increment the current
        // ordinal
        func (o *Ordinal) Increment() {
            atomic.AddUint64(&o.ordinal, 1)
        }
```

1.  创建一个名为`example`的新目录并进入。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "fmt"
            "sync"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter10/atomic"
        )

        func main() {
            o := atomic.NewOrdinal()
            m := atomic.NewSafeMap()
            o.Init(1123)
            fmt.Println("initial ordinal is:", o.GetOrdinal())
            wg := sync.WaitGroup{}
            for i := 0; i < 10; i++ {
                wg.Add(1)
                go func(i int) {
                    defer wg.Done()
                    m.Set(fmt.Sprint(i), "success")
                    o.Increment()
                }(i)
            }

            wg.Wait()
            for i := 0; i < 10; i++ {
                v, err := m.Get(fmt.Sprint(i))
                if err != nil || v != "success" {
                    panic(err)
                }
            }
            fmt.Println("final ordinal is:", o.GetOrdinal())
            fmt.Println("all keys found and marked as: 'success'")
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

现在你应该看到以下输出：

```go
$ go run main.go
initial ordinal is: 1123
final ordinal is: 1133
all keys found and marked as: 'success'
```

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶级配方目录中。

1.  如果你复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

对于我们的 map 配方，我们使用了`ReadWrite`互斥锁。这个互斥锁的思想是任意数量的读取者可以获取读取锁，但只有一个写入者可以获取写入锁。此外，当其他人（读取者或写入者）拥有锁时，写入者不能获取锁。这很有用，因为读取非常快速且非阻塞，与标准互斥锁相比。每当我们想要设置数据时，我们使用`Lock()`对象，每当我们想要读取数据时，我们使用`RLock()`。关键是你最终要使用`Unlock()`或`RUnlock()`，这样你就不会使你的应用程序死锁。延迟的`Unlock()`对象可能很有用，但可能比手动调用`Unlock()`慢。

当你想要将额外的操作与锁定的值分组时，这种模式可能不够灵活。例如，在某些情况下，你可能想要锁定，进行一些额外的处理，只有在完成这些处理后才解锁。对于你的设计来说，考虑这一点是很重要的。

`sync/atmoic`包被`Ordinal`用来获取和设置值。还有原子比较操作，比如`atomic.CompareAndSwapUInt64()`，非常有价值。这个配方允许只能在`Ordinal`对象上调用`Init`一次；否则，它只能被原子地递增。

我们循环创建 10 个 Goroutines（与`sync.Waitgroup`同步），并展示序数正确递增了 10 次，我们的 map 中的每个键都被适当地设置。

# 使用上下文包

本书中的几个配方都使用了`context`包。这个配方将探讨创建和管理上下文的基础知识。理解上下文的一个很好的参考是[`blog.golang.org/context`](https://blog.golang.org/context)。自从写这篇博客以来，上下文已经从`net/context`移动到一个叫做`context`的包中。这在与 GRPC 等第三方库交互时仍然偶尔会引起问题。

这个配方将探讨为上下文设置和获取值，取消和超时。

# 如何做...

这些步骤涵盖了编写和运行你的应用程序：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/context`的新目录并进入。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/context 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/context    
```

1.  从`~/projects/go-programming-cookbook-original/chapter10/context`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`values.go`的文件，内容如下：

```go
        package context

        import "context"

        type key string

        const (
            timeoutKey key = "TimeoutKey"
            deadlineKey key = "DeadlineKey"
        )

        // Setup sets some values
        func Setup(ctx context.Context) context.Context {

            ctx = context.WithValue(ctx, timeoutKey,
            "timeout exceeded")
            ctx = context.WithValue(ctx, deadlineKey,
            "deadline exceeded")

            return ctx
        }

        // GetValue grabs a value given a key and
        // returns a string representation of the
        // value
        func GetValue(ctx context.Context, k key) string {

            if val, ok := ctx.Value(k).(string); ok {
                return val
            }
            return ""

        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package context

        import (
            "context"
            "fmt"
            "math/rand"
            "time"
        )

        // Exec sets two random timers and prints
        // a different context value for whichever
        // fires first
        func Exec() {
            // a base context
            ctx := context.Background()
            ctx = Setup(ctx)

            rand.Seed(time.Now().UnixNano())

            timeoutCtx, cancel := context.WithTimeout(ctx, 
            (time.Duration(rand.Intn(2)) * time.Millisecond))
            defer cancel()

            deadlineCtx, cancel := context.WithDeadline(ctx, 
            time.Now().Add(time.Duration(rand.Intn(2))
            *time.Millisecond))
            defer cancel()

            for {
                select {
                    case <-timeoutCtx.Done():
                    fmt.Println(GetValue(ctx, timeoutKey))
                    return
                    case <-deadlineCtx.Done():
                        fmt.Println(GetValue(ctx, deadlineKey))
                        return
                }
            }
        }
```

1.  创建一个名为`example`的新目录并进入。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

            import "github.com/PacktPublishing/
                    Go-Programming-Cookbook-Second-Edition/
                    chapter10/context"

        func main() {
            context.Exec()
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

现在你应该看到以下输出：

```go
$ go run main.go
timeout exceeded
      OR
$ go run main.go
deadline exceeded
```

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶级配方目录中。

1.  如果你复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

当使用上下文值时，最好创建一个新类型来表示键。在这种情况下，我们创建了一个`key`类型，然后声明了一些对应的`const`值来表示所有可能的键。

在这种情况下，我们使用`Setup()`函数同时初始化所有的键/值对。在修改上下文时，函数通常需要一个`context`参数并返回一个`context`值。因此，签名通常如下所示：

```go
func ModifyContext(ctx context.Context) context.Context
```

有时，这些方法还会返回错误或`cancel()`函数，例如`context.WithCancel`、`context.WithTimeout`和`context.WithDeadline`的情况。所有子上下文都继承父上下文的属性。

在这个示例中，我们创建了两个子上下文，一个带有截止日期，一个带有超时。我们将这些超时设置为随机范围，然后在接收到任何一个超时时终止。最后，我们提取了给定键的值并打印出来。

# 执行通道的状态管理

在 Go 中，通道可以是任何类型。结构体通道允许您通过单个消息传递大量状态。本示例将探讨使用通道传递复杂请求结构并在复杂响应结构中返回它们的结果。

在下一个示例中，*使用工作池设计模式*，这种价值变得更加明显，因为您可以创建能够执行各种任务的通用工作程序。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/state`的新目录并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/state 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/state    
```

1.  复制`~/projects/go-programming-cookbook-original/chapter10/state`中的测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`state.go`的文件，内容如下：

```go
        package state

        type op string

        const (
            // Add values
            Add op = "add"
            // Subtract values
            Subtract = "sub"
            // Multiply values
            Multiply = "mult"
            // Divide values
            Divide = "div"
        )

        // WorkRequest perform an op
        // on two values
        type WorkRequest struct {
            Operation op
            Value1 int64
            Value2 int64
        }

        // WorkResponse returns the result
        // and any errors
        type WorkResponse struct {
            Wr *WorkRequest
            Result int64
            Err error
        }
```

1.  创建一个名为`processor.go`的文件，内容如下：

```go
        package state

        import "context"

        // Processor routes work to Process
        func Processor(ctx context.Context, in chan *WorkRequest, out 
        chan *WorkResponse) {
            for {
                select {
                    case <-ctx.Done():
                        return
                    case wr := <-in:
                        out <- Process(wr)
                }
            }
        }
```

1.  创建一个名为`process.go`的文件，内容如下：

```go
        package state

        import "errors"

        // Process switches on operation type
        // Then does work
        func Process(wr *WorkRequest) *WorkResponse {
            resp := WorkResponse{Wr: wr}

            switch wr.Operation {
                case Add:
                    resp.Result = wr.Value1 + wr.Value2
                case Subtract:
                    resp.Result = wr.Value1 - wr.Value2
                case Multiply:
                    resp.Result = wr.Value1 * wr.Value2
                case Divide:
                    if wr.Value2 == 0 {
                        resp.Err = errors.New("divide by 0")
                        break
                    }
                    resp.Result = wr.Value1 / wr.Value2
                    default:
                        resp.Err = errors.New("unsupported operation")
            }
            return &resp
        }
```

1.  创建一个名为`example`的新目录并进入该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "context"
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter10/state"
        )

        func main() {
            in := make(chan *state.WorkRequest, 10)
            out := make(chan *state.WorkResponse, 10)
            ctx := context.Background()
            ctx, cancel := context.WithCancel(ctx)
            defer cancel()

            go state.Processor(ctx, in, out)

            req := state.WorkRequest{state.Add, 3, 4}
            in <- &req

            req2 := state.WorkRequest{state.Subtract, 5, 2}
            in <- &req2

            req3 := state.WorkRequest{state.Multiply, 9, 9}
            in <- &req3

            req4 := state.WorkRequest{state.Divide, 8, 2}
            in <- &req4

            req5 := state.WorkRequest{state.Divide, 8, 0}
            in <- &req5

            for i := 0; i < 5; i++ {
                resp := <-out
                fmt.Printf("Request: %v; Result: %v, Error: %vn",
                resp.Wr, resp.Result, resp.Err)
            }
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

现在应该看到以下输出：

```go
$ go run main.go
Request: &{add 3 4}; Result: 7, Error: <nil>
Request: &{sub 5 2}; Result: 3, Error: <nil>
Request: &{mult 9 9}; Result: 81, Error: <nil>
Request: &{div 8 2}; Result: 4, Error: <nil>
Request: &{div 8 0}; Result: 0, Error: divide by 0
```

1.  `go.mod`文件可能会被更新，顶级示例目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

本示例中的`Processor()`函数是一个循环函数，直到其上下文被取消为止，可以通过显式调用取消或超时来取消。它将所有工作分派给`Process()`，当给定各种操作时，它可以处理不同的函数。也可以让每个这些情况分派另一个函数，以获得更模块化的代码。

最终，响应被返回到响应通道，并且我们在最后循环打印所有结果。我们还演示了`divide by 0`示例中的错误情况。

# 使用工作池设计模式

工作池设计模式是一种将长时间运行的 Goroutines 作为工作程序分派的模式。这些工作程序可以使用多个通道处理各种工作，也可以使用描述类型的有状态请求结构，如前面的示例所述。本示例将创建有状态的工作程序，并演示如何协调和启动多个工作程序，它们都在同一个通道上并发处理请求。这些工作程序将是`crypto`工作程序，就像在 Web 身份验证应用程序中一样。它们的目的将是使用`bcrypt`包对明文字符串进行哈希处理，并将文本密码与哈希进行比较。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/pool`的新目录并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/pool 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/pool    
```

1.  复制`~/projects/go-programming-cookbook-original/chapter10/pool`中的测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`worker.go`的文件，其中包含以下内容：

```go
        package pool

        import (
            "context"
            "fmt"
        )

        // Dispatch creates numWorker workers, returns a cancel 
        // function channels for adding work and responses, 
        // cancel must be called
        func Dispatch(numWorker int) (context.CancelFunc, chan 
        WorkRequest, chan WorkResponse) {
            ctx := context.Background()
            ctx, cancel := context.WithCancel(ctx)
            in := make(chan WorkRequest, 10)
            out := make(chan WorkResponse, 10)

            for i := 0; i < numWorker; i++ {
                go Worker(ctx, i, in, out)
            }
            return cancel, in, out
        }

        // Worker loops forever and is part of the worker pool
        func Worker(ctx context.Context, id int, in chan WorkRequest, 
        out chan WorkResponse) {
            for {
                select {
                    case <-ctx.Done():
                        return
                    case wr := <-in:
                        fmt.Printf("worker id: %d, performing %s
                        workn", id, wr.Op)
                        out <- Process(wr)
                }
            }
        }
```

1.  创建一个名为`work.go`的文件，其中包含以下内容：

```go
        package pool

        import "errors"

        type op string

        const (
            // Hash is the bcrypt work type
            Hash op = "encrypt"
            // Compare is bcrypt compare work
            Compare = "decrypt"
        )

        // WorkRequest is a worker req
        type WorkRequest struct {
            Op op
            Text []byte
            Compare []byte // optional
        }

        // WorkResponse is a worker resp
        type WorkResponse struct {
            Wr WorkRequest
            Result []byte
            Matched bool
            Err error
        }

        // Process dispatches work to the worker pool channel
        func Process(wr WorkRequest) WorkResponse {
            switch wr.Op {
            case Hash:
                return hashWork(wr)
            case Compare:
                return compareWork(wr)
            default:
                return WorkResponse{Err: errors.New("unsupported 
                operation")}
            }
        }
```

1.  创建一个名为`crypto.go`的文件，其中包含以下内容：

```go
        package pool

        import "golang.org/x/crypto/bcrypt"

        func hashWork(wr WorkRequest) WorkResponse {
            val, err := bcrypt.GenerateFromPassword(wr.Text, 
            bcrypt.DefaultCost)
            return WorkResponse{
                Result: val,
                Err: err,
                Wr: wr,
            }
        }

        func compareWork(wr WorkRequest) WorkResponse {
            var matched bool
            err := bcrypt.CompareHashAndPassword(wr.Compare, wr.Text)
            if err == nil {
                matched = true
            }
            return WorkResponse{
                Matched: matched,
                Err: err,
                Wr: wr,
            }
        }
```

1.  创建一个名为`example`的新目录，并进入该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter10/pool"
        )

        func main() {
            cancel, in, out := pool.Dispatch(10)
            defer cancel()

            for i := 0; i < 10; i++ {
                in <- pool.WorkRequest{Op: pool.Hash, Text: 
                []byte(fmt.Sprintf("messages %d", i))}
            }

            for i := 0; i < 10; i++ {
                res := <-out
                if res.Err != nil {
                    panic(res.Err)
                }
                in <- pool.WorkRequest{Op: pool.Compare, Text: 
                res.Wr.Text, Compare: res.Result}
            }

            for i := 0; i < 10; i++ {
                res := <-out
                if res.Err != nil {
                    panic(res.Err)
                }
                fmt.Printf("string: "%s"; matched: %vn", 
                string(res.Wr.Text), res.Matched)
            }
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

现在你应该看到以下输出：

```go
$ go run main.go
worker id: 9, performing encrypt work
worker id: 5, performing encrypt work
worker id: 2, performing encrypt work
worker id: 8, performing encrypt work
worker id: 6, performing encrypt work
worker id: 1, performing encrypt work
worker id: 0, performing encrypt work
worker id: 4, performing encrypt work
worker id: 3, performing encrypt work
worker id: 7, performing encrypt work
worker id: 2, performing decrypt work
worker id: 6, performing decrypt work
worker id: 8, performing decrypt work
worker id: 1, performing decrypt work
worker id: 0, performing decrypt work
worker id: 9, performing decrypt work
worker id: 3, performing decrypt work
worker id: 4, performing decrypt work
worker id: 7, performing decrypt work
worker id: 5, performing decrypt work
string: "messages 9"; matched: true
string: "messages 3"; matched: true
string: "messages 4"; matched: true
string: "messages 0"; matched: true
string: "messages 1"; matched: true
string: "messages 8"; matched: true
string: "messages 5"; matched: true
string: "messages 7"; matched: true
string: "messages 2"; matched: true
string: "messages 6"; matched: true
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶层示例目录中。

1.  如果你复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

这个示例使用`Dispatch()`方法在单个输入通道、输出通道和连接到单个`cancel()`函数上创建多个工作人员。如果你想为不同的目的创建不同的池，这个方法就可以使用。例如，你可以通过使用单独的池创建 10 个`crypto`和 20 个`compare`工作人员。对于这个示例，我们使用一个单一的池，将哈希请求发送给工作人员，检索响应，然后将`compare`请求发送到同一个池中。因此，执行工作的工作人员每次都会不同，但它们都能执行任何类型的工作。

这种方法的优点是，这两种请求都允许并行处理，并且还可以控制最大并发数。限制 Goroutines 的最大数量对于限制内存也很重要。我选择了`crypto`作为这个示例，因为`crypto`是一个很好的例子，它可以通过为每个新请求启动一个新的 Goroutine 来压倒你的 CPU 或内存；例如，在一个 web 服务中。

# 使用工作人员创建管道

这个示例演示了创建工作池组并将它们连接在一起形成一个管道。对于这个示例，我们将两个池连接在一起，但这种模式可以用于更复杂的操作，类似于中间件。

工作池对于保持工作人员相对简单并进一步控制并发非常有用。例如，将日志串行化，同时并行化其他操作可能很有用。对于更昂贵的操作，拥有一个较小的池也可能很有用，这样你就不会过载机器资源。

# 操作步骤如下...

这些步骤涵盖了编写和运行你的应用程序：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter10/pipeline`的新目录，并进入该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/pipeline 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter10/pipeline    
```

1.  复制`~/projects/go-programming-cookbook-original/chapter10/pipeline`中的测试，或者利用这个机会编写一些你自己的代码！

1.  创建一个名为`worker.go`的文件，其中包含以下内容：

```go
        package pipeline

        import "context"

        // Worker have one role
        // that is determined when
        // Work is called
        type Worker struct {
            in chan string
            out chan string
        }

        // Job is a job a worker can do
        type Job string

        const (
            // Print echo's all input to
            // stdout
            Print Job = "print"
            // Encode base64 encodes input
            Encode Job = "encode"
        )

        // Work is how to dispatch a worker, they are assigned
        // a job here
        func (w *Worker) Work(ctx context.Context, j Job) {
            switch j {
                case Print:
                    w.Print(ctx)
                case Encode:
                    w.Encode(ctx)
                default:
                    return
            }
        }
```

1.  创建一个名为`print.go`的文件，其中包含以下内容：

```go
        package pipeline

        import (
            "context"
            "fmt"
        )

        // Print prints w.in and repalys it
        // on w.out
        func (w *Worker) Print(ctx context.Context) {
            for {
                select {
                    case <-ctx.Done():
                        return
                    case val := <-w.in:
                        fmt.Println(val)
                        w.out <- val
                }
            }
        }
```

1.  创建一个名为`encode.go`的文件，其中包含以下内容：

```go
        package pipeline

        import (
            "context"
            "encoding/base64"
            "fmt"
        )

        // Encode takes plain text as int
        // and returns "string => <base64 string encoding>
        // as out
        func (w *Worker) Encode(ctx context.Context) {
            for {
                select {
                    case <-ctx.Done():
                        return
                    case val := <-w.in:
                        w.out <- fmt.Sprintf("%s => %s", val, 
                        base64.StdEncoding.EncodeToString([]byte(val)))
                }
            }
        }
```

1.  创建一个名为`pipeline.go`的文件，其中包含以下内容：

```go
        package pipeline

        import "context"

        // NewPipeline initializes the workers and
        // connects them, it returns the input of the pipeline
        // and the final output
        func NewPipeline(ctx context.Context, numEncoders, numPrinters 
        int) (chan string, chan string) {
            inEncode := make(chan string, numEncoders)
            inPrint := make(chan string, numPrinters)
            outPrint := make(chan string, numPrinters)
            for i := 0; i < numEncoders; i++ {
                w := Worker{
                    in: inEncode,
                    out: inPrint,
                }
                go w.Work(ctx, Encode)
            }

            for i := 0; i < numPrinters; i++ {
                w := Worker{
                    in: inPrint,
                   out: outPrint,
                }
                go w.Work(ctx, Print)
            }
            return inEncode, outPrint
        }
```

1.  创建一个名为`example`的新目录，并进入该目录。

1.  创建一个名为`main.go`的文件，其中包含以下内容：

```go
        package main

        import (
            "context"
            "fmt"

            "github.com/PacktPublishing/
             Go-Programming-Cookbook-Second-Edition/
             chapter10/pipeline"
        )

        func main() {
            ctx := context.Background()
            ctx, cancel := context.WithCancel(ctx)
            defer cancel()

            in, out := pipeline.NewPipeline(ctx, 10, 2)

            go func() {
                for i := 0; i < 20; i++ {
                    in <- fmt.Sprint("Message", i)
                }
            }()

            for i := 0; i < 20; i++ {
                <-out
            }
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

现在你应该看到以下输出：

```go
$ go run main.go
Message3 => TWVzc2FnZTM=
Message7 => TWVzc2FnZTc=
Message8 => TWVzc2FnZTg=
Message9 => TWVzc2FnZTk=
Message5 => TWVzc2FnZTU=
Message11 => TWVzc2FnZTEx
Message10 => TWVzc2FnZTEw
Message4 => TWVzc2FnZTQ=
Message12 => TWVzc2FnZTEy
Message6 => TWVzc2FnZTY=
Message14 => TWVzc2FnZTE0
Message13 => TWVzc2FnZTEz
Message0 => TWVzc2FnZTA=
Message15 => TWVzc2FnZTE1
Message1 => TWVzc2FnZTE=
Message17 => TWVzc2FnZTE3
Message16 => TWVzc2FnZTE2
Message19 => TWVzc2FnZTE5
Message18 => TWVzc2FnZTE4
Message2 => TWVzc2FnZTI=
```

1.  `go.mod`文件可能会被更新，`go.sum`文件现在应该存在于顶层示例目录中。

1.  如果你复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

`main`包创建了一个包含 10 个编码器和 2 个打印机的管道。它在输入通道上排队了 20 个字符串，并等待在输出通道上获得 20 个响应。如果消息到达输出通道，表示它们已经成功通过整个管道。

`NewPipeline` 函数用于连接管道。它确保通道以适当的缓冲区大小创建，并且一些池的输出通道连接到其他池的适当输入通道。还可以通过在每个工作器上使用输入通道数组和输出通道数组，多个命名通道，或通道映射来扩展管道。这将允许诸如在每个步骤发送消息到记录器之类的操作。
